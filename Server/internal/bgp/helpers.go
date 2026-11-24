// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"lg-for-bgp/internal/models"
)

var reSafeVRFName = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

const (
	defaultFilterRouteLimit = 50
	maxFilterRouteLimit     = 5000
)

func clampFilterRouteLimit(v int) int {
	if v <= 0 {
		return defaultFilterRouteLimit
	}
	if v > maxFilterRouteLimit {
		return maxFilterRouteLimit
	}
	return v
}

func (e *Engine) filterRouteLimits() (int, int) {
	if e == nil || e.store == nil {
		return defaultFilterRouteLimit, defaultFilterRouteLimit
	}
	settings := e.store.GetSettings()
	return clampFilterRouteLimit(settings.MaxFilterRoutesV4), clampFilterRouteLimit(settings.MaxFilterRoutesV6)
}

func formatDualStackFilterSummary(target string, v4Count, v6Count int) string {
	switch {
	case v4Count > 0 && v6Count > 0:
		return fmt.Sprintf("Filter: %s (%d IPv4 + %d IPv6 routes)", target, v4Count, v6Count)
	case v4Count > 0:
		return fmt.Sprintf("Filter: %s (%d IPv4 routes)", target, v4Count)
	case v6Count > 0:
		return fmt.Sprintf("Filter: %s (%d IPv6 routes)", target, v6Count)
	default:
		return "No matching route"
	}
}

// isGlobalRIB returns true when VRFName is empty or set to "global" / "default" / "master"
// indicating a single-table router/RR without VRFs.
func isGlobalRIB(vrfName string) bool {
	v := strings.ToLower(strings.TrimSpace(vrfName))
	return v == "" || v == "global" || v == "default" || v == "master" || v == "master4" || v == "master6"
}

// resolveVRFName returns the VRF / RIB table name configured on the RouteViewMeta.
// Returns "global" when configured for a single global routing table.
func resolveVRFName(view models.RouteViewMeta) string {
	vrf := strings.TrimSpace(view.VRFName)
	if vrf == "" {
		vrf = strings.TrimSpace(view.JunosContextName)
	}
	if isGlobalRIB(vrf) {
		return "global"
	}
	return vrf
}

// ASPathQuery represents a parsed AS-Path filter expression with unified anchor semantics
// across GoBGP, BIRD 2, and FRRouting:
//   - AnchorStart (^): matches paths whose entry/neighbor ASN starts with ASNs
//   - AnchorEnd   ($): matches paths whose origin/last ASN ends with ASNs
type ASPathQuery struct {
	AnchorStart bool
	AnchorEnd   bool
	Tokens      []string
	ASNs        []uint32
}

// ParseASPathQuery parses a validated AS-Path query string into structured tokens and ^ / $ anchors.
func ParseASPathQuery(raw string) (ASPathQuery, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ASPathQuery{}, false
	}
	q := ASPathQuery{
		AnchorStart: strings.HasPrefix(trimmed, "^"),
		AnchorEnd:   strings.HasSuffix(trimmed, "$"),
	}
	body := strings.NewReplacer("^", " ", "$", " ", "_", " ", ",", " ").Replace(trimmed)
	for _, tok := range strings.Fields(body) {
		upper := strings.ToUpper(tok)
		if strings.HasPrefix(upper, "AS") && len(tok) > 2 {
			tok = tok[2:]
		}
		tok = strings.Trim(tok, ".*+?[]()-")
		if tok == "" {
			continue
		}
		n, err := strconv.ParseUint(tok, 10, 32)
		if err != nil || n == 0 {
			return ASPathQuery{}, false
		}
		q.Tokens = append(q.Tokens, strconv.FormatUint(n, 10))
		q.ASNs = append(q.ASNs, uint32(n))
	}
	if len(q.ASNs) == 0 {
		return ASPathQuery{}, false
	}
	return q, true
}

// MatchASSequence evaluates whether a route's ordered ASN sequence satisfies an ASPathQuery (including ^ and $ anchors).
func MatchASSequence(routeASNs []uint32, q ASPathQuery) bool {
	k := len(q.ASNs)
	n := len(routeASNs)
	if k == 0 || n < k {
		return false
	}
	eqSlice := func(a, b []uint32) bool {
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	switch {
	case q.AnchorStart && q.AnchorEnd:
		return n == k && eqSlice(routeASNs, q.ASNs)
	case q.AnchorStart:
		return eqSlice(routeASNs[:k], q.ASNs)
	case q.AnchorEnd:
		return eqSlice(routeASNs[n-k:], q.ASNs)
	default:
		for start := 0; start <= n-k; start++ {
			if eqSlice(routeASNs[start:start+k], q.ASNs) {
				return true
			}
		}
		return false
	}
}

// BuildBird2ASPathPattern constructs a BIRD 2 bgp_path mask (e.g. "[= * 4134 =]" for "4134$").
func BuildBird2ASPathPattern(cleaned string) string {
	q, ok := ParseASPathQuery(cleaned)
	if !ok {
		return ""
	}
	seq := strings.Join(q.Tokens, " ")
	switch {
	case q.AnchorStart && q.AnchorEnd:
		return fmt.Sprintf("[= %s =]", seq)
	case q.AnchorStart:
		return fmt.Sprintf("[= %s * =]", seq)
	case q.AnchorEnd:
		return fmt.Sprintf("[= * %s =]", seq)
	default:
		return fmt.Sprintf("[= * %s * =]", seq)
	}
}

// BuildFRRASPathRegexp constructs a safe FRR BGP AS-Path regular expression preserving ^ and $ anchors.
func BuildFRRASPathRegexp(cleaned string) string {
	q, ok := ParseASPathQuery(cleaned)
	if !ok {
		return ""
	}
	prefixAnchor := "_"
	if q.AnchorStart {
		prefixAnchor = "^"
	}
	suffixAnchor := "_"
	if q.AnchorEnd {
		suffixAnchor = "$"
	}
	return prefixAnchor + strings.Join(q.Tokens, "_") + suffixAnchor
}

func wellKnownCommunityTuple(comm string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(comm)) {
	case "no-export":
		return "(65535, 65281)", true
	case "no-advertise":
		return "(65535, 65282)", true
	case "blackhole":
		return "(65535, 666)", true
	case "graceful-shutdown":
		return "(65535, 0)", true
	}
	return "", false
}
