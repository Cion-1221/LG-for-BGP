// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

var reSafeVRFName = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

const maxDriverFilterMatches = 50

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

func extractSafeASPathTokens(cleaned string) []string {
	replaced := strings.NewReplacer("^", " ", "$", " ", "_", " ", ",", " ").Replace(cleaned)
	fields := strings.Fields(replaced)
	var out []string
	for _, tok := range fields {
		upper := strings.ToUpper(tok)
		if strings.HasPrefix(upper, "AS") && len(tok) > 2 {
			tok = tok[2:]
		}
		tok = strings.Trim(tok, ".*+?[]()-")
		if tok == "" {
			continue
		}
		if _, err := strconv.ParseUint(tok, 10, 32); err == nil {
			out = append(out, tok)
		}
	}
	return out
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

// ==============================================================================
// BIRD 2 DRIVER (Local `birdc -r` OR Remote `lg-agent`)
// Supports: prefix, aspath (single ASN & multi-ASN sequence), community (Standard, Large, Well-Known), and Live Neighbors
// ==============================================================================

func (e *Engine) queryLiveBird2VRF(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgent(ctx, rrNode, "bird2", view, queryType, target)
	}
	return e.RunLocalBird2Query(ctx, rrNode, view, queryType, target)
}

// RunLocalBird2Query executes a read-only `birdc -r` query locally (reused by both lg-server and lg-agent).
func (e *Engine) RunLocalBird2Query(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	birdcBin, err := exec.LookPath("birdc")
	if err != nil {
		return nil, "", "", false
	}

	vrfName := resolveVRFName(view)
	tableClause := ""
	if !isGlobalRIB(vrfName) {
		if !reSafeVRFName.MatchString(vrfName) {
			return nil, "", "", false
		}
		tableClause = fmt.Sprintf("table '%s' ", vrfName)
	}

	timeout := 5 * time.Second
	var birdCmd string
	switch queryType {
	case "prefix":
		normalized, _, _, errVal := security.ValidatePrefixOrIP(target)
		if errVal != nil {
			return nil, "", "", false
		}
		birdCmd = fmt.Sprintf("show route %sfor %s all", tableClause, normalized)
	case "aspath":
		timeout = 25 * time.Second
		cleaned, errVal := security.ValidateASPathOrASN(target)
		if errVal != nil {
			return nil, "", "", false
		}
		asTokens := extractSafeASPathTokens(cleaned)
		if len(asTokens) == 0 {
			return nil, "", "", false
		}
		birdCmd = fmt.Sprintf("show route %swhere bgp_path ~ [= * %s * =] all", tableClause, strings.Join(asTokens, " "))
	case "community":
		timeout = 25 * time.Second
		cleaned, errVal := security.ValidateCommunity(target)
		if errVal != nil {
			return nil, "", "", false
		}
		if wk, ok := wellKnownCommunityTuple(cleaned); ok {
			birdCmd = fmt.Sprintf("show route %swhere %s ~ bgp_community all", tableClause, wk)
		} else {
			parts := strings.Split(cleaned, ":")
			switch len(parts) {
			case 2:
				birdCmd = fmt.Sprintf("show route %swhere (%s, %s) ~ bgp_community all", tableClause, parts[0], parts[1])
			case 3:
				birdCmd = fmt.Sprintf("show route %swhere (%s, %s, %s) ~ bgp_large_community all", tableClause, parts[0], parts[1], parts[2])
			default:
				return nil, "", "", false
			}
		}
	default:
		return nil, "", "", false
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var birdArgs []string
	sock := strings.TrimSpace(rrNode.Endpoint)
	if sock != "" && !strings.EqualFold(sock, "local") && !strings.Contains(sock, ":") {
		birdArgs = append(birdArgs, "-s", sock)
	}
	birdArgs = append(birdArgs, "-r", birdCmd)

	cmd := exec.CommandContext(cctx, birdcBin, birdArgs...)
	outBytes, err := cmd.Output()
	if err != nil || len(outBytes) == 0 {
		return nil, "", "", false
	}

	rawOut := string(outBytes)
	if strings.Contains(rawOut, "syntax error") || strings.Contains(rawOut, "Unable to connect") {
		return nil, "", "", false
	}
	if strings.Contains(rawOut, "Network not in table") {
		return []models.BGPRoutePath{}, "No matching route", rawOut, true
	}

	limit := 0
	if queryType != "prefix" {
		limit = maxDriverFilterMatches
	}
	paths, matched, clippedRaw := e.parseBird2Output(rawOut, view, target, limit)
	if len(paths) == 0 {
		return []models.BGPRoutePath{}, "No matching route", rawOut, true
	}
	if queryType != "prefix" {
		matched = fmt.Sprintf("Filter: %s (%d routes)", target, len(paths))
	}
	return paths, matched, clippedRaw, true
}

func (e *Engine) parseBird2Output(rawOut string, view models.RouteViewMeta, target string, maxPaths int) ([]models.BGPRoutePath, string, string) {
	lines := strings.Split(rawOut, "\n")
	var paths []models.BGPRoutePath
	var matchedPrefix string
	var cur *models.BGPRoutePath
	var curComms []string
	var keptLines []string
	seq := uint32(1)
	truncated := false

	flush := func() {
		if cur != nil {
			if maxPaths <= 0 || len(paths) < maxPaths {
				cur.Communities = e.TranslateCommunities(curComms)
				paths = append(paths, *cur)
			} else {
				truncated = true
			}
			cur = nil
			curComms = nil
		}
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "BIRD ") || strings.HasPrefix(line, "Table ") {
			continue
		}
		isHeader := !strings.HasPrefix(rawLine, "\t") && !strings.HasPrefix(rawLine, " ") && (strings.Contains(line, "unicast") || strings.Contains(line, " ["))
		if isHeader {
			flush()
			if maxPaths > 0 && len(paths) >= maxPaths {
				truncated = true
				break
			}
			fields := strings.Fields(line)
			if len(fields) > 0 && (strings.Contains(fields[0], "/") || strings.Contains(fields[0], ":")) {
				matchedPrefix = fields[0]
			}
			if matchedPrefix == "" {
				matchedPrefix = target
			}
			best := strings.Contains(line, " * ")
			fam := "ipv4"
			if strings.Contains(matchedPrefix, ":") {
				fam = "ipv6"
			}
			cur = &models.BGPRoutePath{
				PathID:         seq,
				Prefix:         matchedPrefix,
				AddressFamily:  fam,
				Best:           best,
				Origin:         "IGP",
				LocalPref:      100,
				PeerIP:         view.JuniperSourceIPv4,
				RPKIStatus:     "NotFound",
				Age:            "Active",
				ValidationNote: "BIRD 2 Route",
			}
			seq++
			keptLines = append(keptLines, rawLine)
			continue
		}
		if cur == nil {
			continue
		}
		keptLines = append(keptLines, rawLine)
		if strings.HasPrefix(line, "BGP.next_hop:") {
			cur.NextHop = strings.TrimSpace(strings.TrimPrefix(line, "BGP.next_hop:"))
		} else if strings.HasPrefix(line, "via ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && cur.NextHop == "" {
				cur.NextHop = parts[1]
			}
		} else if strings.HasPrefix(line, "BGP.local_pref:") {
			if v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "BGP.local_pref:")), 10, 32); err == nil {
				cur.LocalPref = uint32(v)
			}
		} else if strings.HasPrefix(line, "BGP.med:") {
			if v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "BGP.med:")), 10, 32); err == nil {
				cur.MED = uint32(v)
			}
		} else if strings.HasPrefix(line, "BGP.as_path:") {
			asStr := strings.TrimSpace(strings.TrimPrefix(line, "BGP.as_path:"))
			cur.ASPathString = asStr
			for _, tok := range strings.Fields(asStr) {
				if n, err := strconv.ParseUint(tok, 10, 32); err == nil {
					hop := e.ResolveASN(uint32(n))
					cur.ASPath = append(cur.ASPath, hop)
					cur.OriginASN = hop.ASN
					cur.OriginName = hop.Name
				}
			}
		} else if strings.HasPrefix(line, "BGP.community:") {
			commRaw := strings.TrimSpace(strings.TrimPrefix(line, "BGP.community:"))
			commRaw = strings.ReplaceAll(commRaw, "(", "")
			commRaw = strings.ReplaceAll(commRaw, ")", "")
			for _, tok := range strings.Fields(commRaw) {
				curComms = append(curComms, strings.ReplaceAll(tok, ",", ":"))
			}
		} else if strings.HasPrefix(line, "BGP.large_community:") {
			commRaw := strings.TrimSpace(strings.TrimPrefix(line, "BGP.large_community:"))
			commRaw = strings.ReplaceAll(commRaw, "(", "")
			commRaw = strings.ReplaceAll(commRaw, ")", "")
			for _, tok := range strings.Fields(commRaw) {
				curComms = append(curComms, strings.ReplaceAll(tok, ",", ":"))
			}
		}
	}
	flush()
	if matchedPrefix == "" {
		matchedPrefix = "No matching route"
	}
	outRaw := rawOut
	if truncated && len(keptLines) > 0 {
		outRaw = strings.Join(keptLines, "\n") + fmt.Sprintf("\n# ... truncated after %d matching routes ...\n", maxPaths)
	}
	return paths, matchedPrefix, outRaw
}

type birdProtocolInfo struct {
	name       string
	state      string
	since      string
	neighborIP string
	neighborAS uint32
	tables     []string
	ipv4Routes int
	ipv6Routes int
}

func (e *Engine) queryLiveBird2Neighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgentNeighbors(ctx, rrNode, "bird2", views)
	}
	return e.RunLocalBird2Neighbors(ctx, rrNode, views)
}

// RunLocalBird2Neighbors queries `birdc -r "show protocols all"` and maps BGP sessions strictly to each bound VRF.
func (e *Engine) RunLocalBird2Neighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	birdcBin, err := exec.LookPath("birdc")
	if err != nil {
		return nil, false
	}

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var birdArgs []string
	sock := strings.TrimSpace(rrNode.Endpoint)
	if sock != "" && !strings.EqualFold(sock, "local") && !strings.Contains(sock, ":") {
		birdArgs = append(birdArgs, "-s", sock)
	}
	birdArgs = append(birdArgs, "-r", "show protocols all")

	outBytes, err := exec.CommandContext(cctx, birdcBin, birdArgs...).Output()
	if err != nil || len(outBytes) == 0 {
		return nil, false
	}
	raw := string(outBytes)
	if strings.Contains(raw, "Unable to connect") {
		return nil, false
	}

	var protos []birdProtocolInfo
	var cur *birdProtocolInfo
	curChan := ""

	flushProto := func() {
		if cur != nil {
			protos = append(protos, *cur)
			cur = nil
			curChan = ""
		}
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "BIRD ") || strings.HasPrefix(trimmed, "Name ") {
			continue
		}
		if !strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t") {
			flushProto()
			fields := strings.Fields(trimmed)
			if len(fields) >= 4 && strings.EqualFold(fields[1], "BGP") {
				since := "-"
				if len(fields) >= 5 {
					since = fields[4]
				}
				state := fields[3]
				if len(fields) >= 6 && strings.EqualFold(fields[5], "Established") {
					state = "Established"
				}
				cur = &birdProtocolInfo{
					name:  fields[0],
					state: state,
					since: since,
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(trimmed, "BGP state:") {
			cur.state = strings.TrimSpace(strings.TrimPrefix(trimmed, "BGP state:"))
		} else if strings.HasPrefix(trimmed, "Neighbor address:") {
			cur.neighborIP = strings.TrimSpace(strings.TrimPrefix(trimmed, "Neighbor address:"))
		} else if strings.HasPrefix(trimmed, "Neighbor AS:") {
			if n, errConv := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(trimmed, "Neighbor AS:")), 10, 32); errConv == nil {
				cur.neighborAS = uint32(n)
			}
		} else if strings.HasPrefix(trimmed, "Channel ") {
			curChan = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "Channel ")))
		} else if strings.HasPrefix(trimmed, "Table:") {
			tbl := strings.TrimSpace(strings.TrimPrefix(trimmed, "Table:"))
			cur.tables = append(cur.tables, tbl)
		} else if strings.HasPrefix(trimmed, "Routes:") {
			// Format: "Routes:         1369039 imported, 0 exported, 1369039 preferred"
			fields := strings.Fields(strings.TrimPrefix(trimmed, "Routes:"))
			if len(fields) > 0 {
				if cnt, errConv := strconv.Atoi(fields[0]); errConv == nil {
					if strings.Contains(curChan, "6") {
						cur.ipv6Routes += cnt
					} else {
						cur.ipv4Routes += cnt
					}
				}
			}
		}
	}
	flushProto()

	summaries := make([]models.BGPNeighborSummary, 0, len(views))
	for _, v := range views {
		vrfName := resolveVRFName(v)
		wantGlobal := isGlobalRIB(vrfName)
		hintIP := strings.TrimSpace(v.JuniperSourceIPv4)

		var matched []birdProtocolInfo
		for _, p := range protos {
			tableMatch := false
			for _, tbl := range p.tables {
				if wantGlobal {
					if isGlobalRIB(tbl) {
						tableMatch = true
						break
					}
				} else if strings.EqualFold(tbl, vrfName) || strings.EqualFold(tbl, vrfName+"_v4") || strings.EqualFold(tbl, vrfName+"_v6") {
					tableMatch = true
					break
				}
			}
			if tableMatch || (!wantGlobal && strings.EqualFold(p.name, vrfName)) {
				if hintIP == "" || p.neighborIP == "" || p.neighborIP == hintIP {
					matched = append(matched, p)
				}
			}
		}

		if len(matched) == 0 {
			summaries = append(summaries, models.BGPNeighborSummary{
				POP:          rrNode.Location,
				RRNodeID:     rrNode.ID,
				RRNodeName:   rrNode.Name,
				EngineType:   "bird2",
				ViewID:       v.ID,
				ViewName:     v.Name,
				VRFName:      v.VRFName,
				JunosContext: fmt.Sprintf("bird2 table %s", vrfName),
				NeighborIP:   hintIP,
				SessionState: "No Peer / Idle",
				Uptime:       "-",
			})
			continue
		}

		for _, p := range matched {
			state := p.state
			if strings.EqualFold(state, "up") {
				state = "Established"
			}
			uptime := "-"
			if strings.EqualFold(state, "Established") {
				uptime = p.since
			}
			summaries = append(summaries, models.BGPNeighborSummary{
				POP:              rrNode.Location,
				RRNodeID:         rrNode.ID,
				RRNodeName:       rrNode.Name,
				EngineType:       "bird2",
				ViewID:           v.ID,
				ViewName:         v.Name,
				VRFName:          v.VRFName,
				JunosContext:     fmt.Sprintf("bird2 %s (%s)", vrfName, p.name),
				NeighborIP:       p.neighborIP,
				PeerASN:          p.neighborAS,
				SessionState:     state,
				Uptime:           uptime,
				AddPathRx:        true,
				NextHopUnchanged: true,
				PrefixesIPv4:     p.ipv4Routes,
				PrefixesIPv6:     p.ipv6Routes,
			})
		}
	}

	return summaries, true
}

// ==============================================================================
// FRRouting (FRR / VyOS) DRIVER (Local `vtysh` OR Remote `lg-agent`)
// Supports: Global RIB, FRR BGP `view <name>`, Linux/VyOS `vrf <name>`,
//           prefix, aspath (regexp), community, large-community, and Live Neighbors
// ==============================================================================

type frrPathJSON struct {
	Bestpath *struct {
		Overall bool `json:"overall"`
	} `json:"bestpath"`
	Best   bool   `json:"bestpath_bool"`
	PathID uint32 `json:"pathId"`
	Origin string `json:"origin"`
	Metric uint32 `json:"metric"`
	LocPrf uint32 `json:"locPrf"`
	Valid  bool   `json:"valid"`
	ASPath *struct {
		String string `json:"string"`
	} `json:"aspath"`
	Nexthops []struct {
		IP  string `json:"ip"`
		AFI string `json:"afi"`
	} `json:"nexthops"`
	Peer *struct {
		PeerID string `json:"peerId"`
	} `json:"peer"`
	Community *struct {
		List []string `json:"list"`
	} `json:"community"`
	LargeCommunity *struct {
		List []string `json:"list"`
	} `json:"largeCommunity"`
}

type frrPrefixJSONResponse struct {
	Prefix string        `json:"prefix"`
	Paths  []frrPathJSON `json:"paths"`
}

type frrTableJSONResponse struct {
	Routes map[string][]frrPathJSON `json:"routes"`
}

type frrSummaryAFJSON struct {
	Peers map[string]struct {
		RemoteAS       uint32 `json:"remoteAs"`
		PfxRcd         int    `json:"pfxRcd"`
		State          string `json:"state"`
		PeerUptime     string `json:"peerUptime"`
		MsgRcvd        int64  `json:"msgRcvd"`
	} `json:"peers"`
}

type frrSummaryJSONResponse struct {
	IPv4Unicast *frrSummaryAFJSON `json:"ipv4Unicast"`
	IPv6Unicast *frrSummaryAFJSON `json:"ipv6Unicast"`
}

func frrScopeClauses(vrfName string) []string {
	if isGlobalRIB(vrfName) {
		return []string{""}
	}
	lower := strings.ToLower(vrfName)
	if strings.HasPrefix(lower, "view:") {
		name := strings.TrimSpace(vrfName[5:])
		if reSafeVRFName.MatchString(name) {
			return []string{"view " + name + " "}
		}
		return nil
	}
	if strings.HasPrefix(lower, "vrf:") {
		name := strings.TrimSpace(vrfName[4:])
		if reSafeVRFName.MatchString(name) {
			return []string{"vrf " + name + " "}
		}
		return nil
	}
	if !reSafeVRFName.MatchString(vrfName) {
		return nil
	}
	// Try both FRR BGP `view` and VyOS/Linux `vrf` automatically!
	return []string{"view " + vrfName + " ", "vrf " + vrfName + " "}
}

func (e *Engine) queryLiveFrrVRF(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgent(ctx, rrNode, "frr", view, queryType, target)
	}
	return e.RunLocalFrrQuery(ctx, rrNode, view, queryType, target)
}

func runVtysh(ctx context.Context, vtyshBin string, baseArgs []string, vtyCmd string) ([]byte, error) {
	args := append(append([]string{}, baseArgs...), "-c", vtyCmd)
	return exec.CommandContext(ctx, vtyshBin, args...).Output()
}

func frrOutputIsScopeError(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "% unknown command") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "can't find") ||
		strings.Contains(lower, "no bgp instance")
}

// RunLocalFrrQuery executes read-only `vtysh` commands locally (supports prefix, aspath, community, and VyOS VRFs).
func (e *Engine) RunLocalFrrQuery(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	vtyshBin, err := exec.LookPath("vtysh")
	if err != nil {
		return nil, "", "", false
	}

	vrfName := resolveVRFName(view)
	clauses := frrScopeClauses(vrfName)
	if len(clauses) == 0 {
		return nil, "", "", false
	}

	var vtyBaseArgs []string
	vtySock := strings.TrimSpace(rrNode.Endpoint)
	if vtySock != "" && !strings.EqualFold(vtySock, "local") && !strings.Contains(vtySock, ":") {
		vtyBaseArgs = append(vtyBaseArgs, "--vty_socket", vtySock)
	}

	timeout := 5 * time.Second
	if queryType == "aspath" || queryType == "community" {
		timeout = 25 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Mode 1: Prefix / IP Longest-Prefix Lookup
	if queryType == "prefix" {
		normalized, fam, _, errVal := security.ValidatePrefixOrIP(target)
		if errVal != nil {
			return nil, "", "", false
		}
		afStr := "ipv4"
		if fam == "ipv6" {
			afStr = "ipv6"
		}

		vtyshAlive := false
		for _, clause := range clauses {
			vtyCmdJSON := fmt.Sprintf("show bgp %s%s unicast %s json", clause, afStr, normalized)
			jsonBytes, err := runVtysh(cctx, vtyshBin, vtyBaseArgs, vtyCmdJSON)
			if err != nil {
				continue
			}
			rawStr := strings.TrimSpace(string(jsonBytes))
			if frrOutputIsScopeError(rawStr) {
				continue
			}
			vtyshAlive = true

			var parsed frrPrefixJSONResponse
			if err := json.Unmarshal(jsonBytes, &parsed); err != nil || len(parsed.Paths) == 0 {
				// Valid JSON with empty paths or "{}" -> route not in table for this scope
				continue
			}

			vtyCmdRaw := fmt.Sprintf("show bgp %s%s unicast %s", clause, afStr, normalized)
			rawBytes, _ := runVtysh(cctx, vtyshBin, vtyBaseArgs, vtyCmdRaw)
			results := e.convertFRRPaths(parsed.Prefix, fam, vrfName, view, parsed.Paths)
			return results, parsed.Prefix, string(rawBytes), true
		}
		if vtyshAlive {
			emptyRaw := fmt.Sprintf("# Node: %s (%s) | Engine: FRR\n# VRF: %s | Target: %s\nNetwork not in table.\n",
				rrNode.Name, rrNode.LoopbackIP, vrfName, normalized)
			return []models.BGPRoutePath{}, "No matching route", emptyRaw, true
		}
		return nil, "", "", false
	}

	// Mode 2 & 3: AS-Path regexp or BGP Community / Large-Community scan
	var filterClause string
	switch queryType {
	case "aspath":
		cleaned, errVal := security.ValidateASPathOrASN(target)
		if errVal != nil {
			return nil, "", "", false
		}
		asTokens := extractSafeASPathTokens(cleaned)
		if len(asTokens) == 0 {
			return nil, "", "", false
		}
		filterClause = fmt.Sprintf("regexp _%s_", strings.Join(asTokens, "_"))
	case "community":
		cleaned, errVal := security.ValidateCommunity(target)
		if errVal != nil {
			return nil, "", "", false
		}
		if strings.Count(cleaned, ":") == 2 {
			filterClause = fmt.Sprintf("large-community %s", cleaned)
		} else {
			filterClause = fmt.Sprintf("community %s", cleaned)
		}
	default:
		return nil, "", "", false
	}

	vtyshAlive := false
	for _, clause := range clauses {
		var results []models.BGPRoutePath
		var rawLines []string
		matchedAnyScope := false

		for _, afStr := range []string{"ipv4", "ipv6"} {
			if len(results) >= maxDriverFilterMatches {
				break
			}
			vtyCmdJSON := fmt.Sprintf("show bgp %s%s unicast %s json", clause, afStr, filterClause)
			jsonBytes, err := runVtysh(cctx, vtyshBin, vtyBaseArgs, vtyCmdJSON)
			if err != nil {
				continue
			}
			rawStr := strings.TrimSpace(string(jsonBytes))
			if frrOutputIsScopeError(rawStr) {
				continue
			}
			vtyshAlive = true
			matchedAnyScope = true

			var tableResp frrTableJSONResponse
			if err := json.Unmarshal(jsonBytes, &tableResp); err != nil || len(tableResp.Routes) == 0 {
				continue
			}

			prefixes := make([]string, 0, len(tableResp.Routes))
			for pfx := range tableResp.Routes {
				prefixes = append(prefixes, pfx)
			}
			sort.Strings(prefixes)

			for _, pfx := range prefixes {
				if len(results) >= maxDriverFilterMatches {
					break
				}
				converted := e.convertFRRPaths(pfx, afStr, vrfName, view, tableResp.Routes[pfx])
				for _, rp := range converted {
					if len(results) >= maxDriverFilterMatches {
						break
					}
					results = append(results, rp)
					sym := "* "
					if rp.Best {
						sym = "*>"
					}
					rawLines = append(rawLines, fmt.Sprintf("%-2s %-22s %-16s %-6d %-6d %s",
						sym, rp.Prefix, rp.NextHop, rp.LocalPref, rp.MED, rp.ASPathString))
				}
			}
		}

		if len(results) > 0 {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("   %-22s %-16s %-6s %-6s %s\n", "Network", "Next Hop", "LocPrf", "MED", "AS_PATH"))
			for _, line := range rawLines {
				sb.WriteString(line + "\n")
			}
			summaryLabel := fmt.Sprintf("Filter: %s (%d routes)", target, len(results))
			return results, summaryLabel, sb.String(), true
		}
		if matchedAnyScope {
			emptyRaw := fmt.Sprintf("# Node: %s (%s) | Engine: FRR\n# VRF: %s | Filter: %s\nNetwork not in table.\n",
				rrNode.Name, rrNode.LoopbackIP, vrfName, target)
			return []models.BGPRoutePath{}, "No matching route", emptyRaw, true
		}
	}

	if vtyshAlive {
		emptyRaw := fmt.Sprintf("# Node: %s (%s) | Engine: FRR\n# VRF: %s | Target: %s\nNetwork not in table.\n",
			rrNode.Name, rrNode.LoopbackIP, vrfName, target)
		return []models.BGPRoutePath{}, "No matching route", emptyRaw, true
	}
	return nil, "", "", false
}

func (e *Engine) convertFRRPaths(prefix, fam, vrfName string, view models.RouteViewMeta, rawPaths []frrPathJSON) []models.BGPRoutePath {
	results := make([]models.BGPRoutePath, 0, len(rawPaths))
	for idx, p := range rawPaths {
		best := (p.Bestpath != nil && p.Bestpath.Overall) || p.Best || idx == 0
		nh := ""
		if len(p.Nexthops) > 0 {
			nh = p.Nexthops[0].IP
		}
		var asns []uint32
		if p.ASPath != nil && p.ASPath.String != "" && p.ASPath.String != "Local" {
			for _, tok := range strings.Fields(p.ASPath.String) {
				if n, errConv := strconv.ParseUint(tok, 10, 32); errConv == nil {
					asns = append(asns, uint32(n))
				}
			}
		}
		var comms []string
		if p.Community != nil {
			comms = append(comms, p.Community.List...)
		}
		if p.LargeCommunity != nil {
			comms = append(comms, p.LargeCommunity.List...)
		}
		peerIP := view.JuniperSourceIPv4
		if p.Peer != nil && p.Peer.PeerID != "" {
			peerIP = p.Peer.PeerID
		}
		pathID := p.PathID
		if pathID == 0 {
			pathID = uint32(idx + 1)
		}
		results = append(results, e.buildPath(
			pathID,
			prefix,
			fam,
			best,
			nh,
			fmt.Sprintf("Original eBGP Next-Hop (FRR %s)", vrfName),
			asns,
			p.LocPrf,
			p.Metric,
			comms,
			peerIP,
			"NotFound",
			"Active",
			"Selected in FRR RIB",
		))
	}
	return results
}

func (e *Engine) queryLiveFrrNeighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgentNeighbors(ctx, rrNode, "frr", views)
	}
	return e.RunLocalFrrNeighbors(ctx, rrNode, views)
}

// RunLocalFrrNeighbors queries `vtysh -c "show bgp [view|vrf <VRF>] summary json"` per bound VRF.
func (e *Engine) RunLocalFrrNeighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	vtyshBin, err := exec.LookPath("vtysh")
	if err != nil {
		return nil, false
	}

	var vtyBaseArgs []string
	vtySock := strings.TrimSpace(rrNode.Endpoint)
	if vtySock != "" && !strings.EqualFold(vtySock, "local") && !strings.Contains(vtySock, ":") {
		vtyBaseArgs = append(vtyBaseArgs, "--vty_socket", vtySock)
	}

	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	// Verify vtysh / bgpd responsiveness
	if _, err := runVtysh(cctx, vtyshBin, vtyBaseArgs, "show bgp summary json"); err != nil {
		return nil, false
	}

	summaries := make([]models.BGPNeighborSummary, 0, len(views))
	for _, v := range views {
		vrfName := resolveVRFName(v)
		clauses := frrScopeClauses(vrfName)
		hintIP := strings.TrimSpace(v.JuniperSourceIPv4)

		type aggPeer struct {
			ip       string
			asn      uint32
			state    string
			uptime   string
			v4       int
			v6       int
			msgRcvd  int64
		}
		peerMap := make(map[string]*aggPeer)

		for _, clause := range clauses {
			cmdStr := fmt.Sprintf("show bgp %ssummary json", clause)
			outBytes, err := runVtysh(cctx, vtyshBin, vtyBaseArgs, cmdStr)
			if err != nil {
				continue
			}
			if frrOutputIsScopeError(string(outBytes)) {
				continue
			}
			var parsed frrSummaryJSONResponse
			if err := json.Unmarshal(outBytes, &parsed); err != nil {
				continue
			}

			collect := func(af *frrSummaryAFJSON, isV6 bool) {
				if af == nil {
					return
				}
				for ip, p := range af.Peers {
					if hintIP != "" && ip != hintIP {
						continue
					}
					ap, exists := peerMap[ip]
					if !exists {
						ap = &aggPeer{ip: ip, asn: p.RemoteAS, state: p.State, uptime: p.PeerUptime}
						peerMap[ip] = ap
					}
					if strings.EqualFold(p.State, "Established") {
						ap.state = "Established"
						ap.uptime = p.PeerUptime
					}
					if isV6 {
						ap.v6 += p.PfxRcd
					} else {
						ap.v4 += p.PfxRcd
					}
					ap.msgRcvd += p.MsgRcvd
				}
			}

			collect(parsed.IPv4Unicast, false)
			collect(parsed.IPv6Unicast, true)
			if len(peerMap) > 0 {
				break
			}
		}

		if len(peerMap) == 0 {
			summaries = append(summaries, models.BGPNeighborSummary{
				POP:          rrNode.Location,
				RRNodeID:     rrNode.ID,
				RRNodeName:   rrNode.Name,
				EngineType:   "frr",
				ViewID:       v.ID,
				ViewName:     v.Name,
				VRFName:      v.VRFName,
				JunosContext: fmt.Sprintf("frr %s", vrfName),
				NeighborIP:   hintIP,
				SessionState: "No Peer / Idle",
				Uptime:       "-",
			})
			continue
		}

		ips := make([]string, 0, len(peerMap))
		for ip := range peerMap {
			ips = append(ips, ip)
		}
		sort.Strings(ips)

		for _, ip := range ips {
			ap := peerMap[ip]
			uptime := ap.uptime
			if !strings.EqualFold(ap.state, "Established") || uptime == "" {
				uptime = "-"
			}
			summaries = append(summaries, models.BGPNeighborSummary{
				POP:              rrNode.Location,
				RRNodeID:         rrNode.ID,
				RRNodeName:       rrNode.Name,
				EngineType:       "frr",
				ViewID:           v.ID,
				ViewName:         v.Name,
				VRFName:          v.VRFName,
				JunosContext:     fmt.Sprintf("frr %s", vrfName),
				NeighborIP:       ap.ip,
				PeerASN:          ap.asn,
				SessionState:     ap.state,
				Uptime:           uptime,
				AddPathRx:        true,
				NextHopUnchanged: true,
				PrefixesIPv4:     ap.v4,
				PrefixesIPv6:     ap.v6,
				UpdatesReceived:  ap.msgRcvd,
			})
		}
	}

	return summaries, true
}
