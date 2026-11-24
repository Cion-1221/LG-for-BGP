// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

// frrBestpathFlag unmarshals FRR's "bestpath" field in both JSON schemas:
//   - Table scans (`regexp`, `community`, `large-community`): `"bestpath": true` (JSON bool)
//   - Single-prefix lookups (`show bgp ... <prefix> json`):   `"bestpath": {"overall": true}` (JSON object)
type frrBestpathFlag bool

func (f *frrBestpathFlag) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = false
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*f = frrBestpathFlag(b)
		return nil
	}
	var obj struct {
		Overall bool `json:"overall"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		*f = frrBestpathFlag(obj.Overall)
		return nil
	}
	*f = false
	return nil
}

type frrPathJSON struct {
	Bestpath     frrBestpathFlag `json:"bestpath"`
	Best         bool            `json:"bestpath_bool"`
	PathID       uint32          `json:"pathId"`
	Origin       string          `json:"origin"`
	Metric       uint32          `json:"metric"`
	LocPrf       uint32          `json:"locPrf"`
	Valid        bool            `json:"valid"`
	RPKIValid    bool            `json:"rpkiValid"`
	RPKIInvalid  bool            `json:"rpkiInvalid"`
	RPKINotFound bool            `json:"rpkiNotFound"`
	Path         string          `json:"path"`
	PeerID       string          `json:"peerId"`
	ASPath       *struct {
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

type frrSummaryAFJSON struct {
	AS    uint32 `json:"as"`
	Peers map[string]struct {
		RemoteAS   uint32 `json:"remoteAs"`
		LocalAS    uint32 `json:"localAs"`
		PfxRcd     int    `json:"pfxRcd"`
		State      string `json:"state"`
		PeerUptime string `json:"peerUptime"`
		MsgRcvd    int64  `json:"msgRcvd"`
	} `json:"peers"`
}

type frrSummaryJSONResponse struct {
	IPv4Unicast *frrSummaryAFJSON `json:"ipv4Unicast"`
	IPv6Unicast *frrSummaryAFJSON `json:"ipv6Unicast"`
}

type frrNeighborDetailJSON struct {
	BgpType              string `json:"bgpType"`
	RemoteAs             uint32 `json:"remoteAs"`
	LocalAs              uint32 `json:"localAs"`
	NeighborCapabilities *struct {
		AddPath map[string]struct {
			RxAdvertisedAndReceived bool `json:"rxAdvertisedAndReceived"`
			RxAdvertised            bool `json:"rxAdvertised"`
			RxReceived              bool `json:"rxReceived"`
		} `json:"addPath"`
	} `json:"neighborCapabilities"`
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
	return []string{"view " + vrfName + " ", "vrf " + vrfName + " "}
}

func (e *Engine) queryLiveFrrVRF(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) (int, string, string, bool) {
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

func formatFRRPathCLILine(pfx, afStr string, p frrPathJSON, isSingle bool, idx int) string {
	best := bool(p.Bestpath) || p.Best || (isSingle && idx == 0)
	sym := "* "
	if best {
		sym = "*>"
	}
	nh := ""
	if len(p.Nexthops) > 0 {
		nh = p.Nexthops[0].IP
	}
	asPathStr := strings.TrimSpace(p.Path)
	if p.ASPath != nil && strings.TrimSpace(p.ASPath.String) != "" {
		asPathStr = strings.TrimSpace(p.ASPath.String)
	}
	var extras []string
	if p.RPKIValid {
		extras = append(extras, "RPKI:Valid")
	} else if p.RPKIInvalid {
		extras = append(extras, "RPKI:Invalid")
	}
	if p.Community != nil && len(p.Community.List) > 0 {
		extras = append(extras, "Comm:"+strings.Join(p.Community.List, ","))
	}
	if p.LargeCommunity != nil && len(p.LargeCommunity.List) > 0 {
		extras = append(extras, "LComm:"+strings.Join(p.LargeCommunity.List, ","))
	}
	extraSuffix := ""
	if len(extras) > 0 {
		extraSuffix = " [" + strings.Join(extras, " ") + "]"
	}
	if afStr == "ipv6" {
		return fmt.Sprintf("%-2s %-36s %-32s %-6d %-6d %s%s",
			sym, pfx, nh, p.LocPrf, p.Metric, asPathStr, extraSuffix)
	}
	return fmt.Sprintf("%-2s %-22s %-16s %-6d %-6d %s%s",
		sym, pfx, nh, p.LocPrf, p.Metric, asPathStr, extraSuffix)
}

// streamFRRTableRoutes streams FRR's `show bgp ... regexp/community ... json` output token-by-token
// via json.Decoder and stops immediately once `maxRoutes` paths are collected, preventing multi-hundred-MB OOM on DFZ tables.
func streamFRRTableRoutes(r io.Reader, afStr string, maxRoutes int) (rawLines []string, alive bool, stopEarly bool) {
	maxRoutes = clampFilterRouteLimit(maxRoutes)
	br := bufio.NewReaderSize(r, 32*1024)
	peekBytes, _ := br.Peek(256)
	peekTrimmed := strings.TrimSpace(string(peekBytes))
	if peekTrimmed == "" {
		return nil, false, false
	}
	if frrOutputIsScopeError(peekTrimmed) || !strings.HasPrefix(peekTrimmed, "{") {
		return nil, false, false
	}

	dec := json.NewDecoder(br)
	tok, err := dec.Token()
	if err != nil {
		return nil, false, false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, false, false
	}
	alive = true

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			break
		}
		key, ok := keyTok.(string)
		if !ok {
			break
		}
		if key != "routes" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				break
			}
			continue
		}

		// Enter "routes": { "<prefix>": [ ... ] }
		rTok, err := dec.Token()
		if err != nil {
			break
		}
		if rTok == nil {
			continue
		}
		if delim, ok := rTok.(json.Delim); !ok || delim != '{' {
			break
		}

		for dec.More() {
			pfxTok, err := dec.Token()
			if err != nil {
				return rawLines, alive, false
			}
			pfx, ok := pfxTok.(string)
			if !ok {
				return rawLines, alive, false
			}
			var paths []frrPathJSON
			if err := dec.Decode(&paths); err != nil {
				return rawLines, alive, false
			}
			for idx, p := range paths {
				rawLines = append(rawLines, formatFRRPathCLILine(pfx, afStr, p, len(paths) == 1, idx))
				if len(rawLines) >= maxRoutes {
					return rawLines, true, true
				}
			}
		}
		break
	}

	return rawLines, alive, false
}

func runStreamingFRRScan(ctx context.Context, vtyshBin string, baseArgs []string, vtyCmd string, afStr string, maxRoutes int) ([]string, bool) {
	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	args := append(append([]string{}, baseArgs...), "-c", vtyCmd)
	cmd := exec.CommandContext(scanCtx, vtyshBin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false
	}
	if err := cmd.Start(); err != nil {
		return nil, false
	}

	lines, alive, stoppedEarly := streamFRRTableRoutes(stdout, afStr, maxRoutes)
	if stoppedEarly {
		// Kill vtysh immediately so it stops dumping the rest of the full routing table
		cancelScan()
	}
	_ = cmd.Wait()
	return lines, alive
}

// RunLocalFrrQuery executes read-only `vtysh` commands locally using configured IPv4/IPv6 filter route limits.
func (e *Engine) RunLocalFrrQuery(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) (int, string, string, bool) {
	maxV4, maxV6 := e.filterRouteLimits()
	return e.RunLocalFrrQueryWithLimits(ctx, rrNode, view, queryType, target, maxV4, maxV6)
}

// RunLocalFrrQueryWithLimits executes read-only `vtysh` commands locally with explicit IPv4/IPv6 route caps.
func (e *Engine) RunLocalFrrQueryWithLimits(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
	maxV4 int,
	maxV6 int,
) (int, string, string, bool) {
	maxV4 = clampFilterRouteLimit(maxV4)
	maxV6 = clampFilterRouteLimit(maxV6)
	vtyshBin, err := exec.LookPath("vtysh")
	if err != nil {
		return 0, "", "", false
	}

	vrfName := resolveVRFName(view)
	clauses := frrScopeClauses(vrfName)
	if len(clauses) == 0 {
		return 0, "", "", false
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
			return 0, "", "", false
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
				continue
			}

			vtyCmdRaw := fmt.Sprintf("show bgp %s%s unicast %s", clause, afStr, normalized)
			rawBytes, _ := runVtysh(cctx, vtyshBin, vtyBaseArgs, vtyCmdRaw)
			return len(parsed.Paths), parsed.Prefix, string(rawBytes), true
		}
		if vtyshAlive {
			emptyRaw := fmt.Sprintf("# Node: %s | Engine: FRR\n# VRF: %s | Target: %s\nNetwork not in table.\n",
				rrNode.Name, vrfName, normalized)
			return 0, "No matching route", emptyRaw, true
		}
		return 0, "", "", false
	}

	// Mode 2 & 3: Streaming AS-Path regexp or BGP Community / Large-Community scan
	var filterClause string
	switch queryType {
	case "aspath":
		cleaned, errVal := security.ValidateASPathOrASN(target)
		if errVal != nil {
			return 0, "", "", false
		}
		expr := BuildFRRASPathRegexp(cleaned)
		if expr == "" {
			return 0, "", "", false
		}
		filterClause = fmt.Sprintf("regexp %s", expr)
	case "community":
		cleaned, errVal := security.ValidateCommunity(target)
		if errVal != nil {
			return 0, "", "", false
		}
		if strings.Count(cleaned, ":") == 2 {
			filterClause = fmt.Sprintf("large-community %s", cleaned)
		} else {
			filterClause = fmt.Sprintf("community %s", cleaned)
		}
	default:
		return 0, "", "", false
	}

	vtyshAlive := false
	for _, clause := range clauses {
		var (
			wg      sync.WaitGroup
			lines4  []string
			lines6  []string
			alive4  bool
			alive6  bool
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			cmd4 := fmt.Sprintf("show bgp %sipv4 unicast %s json", clause, filterClause)
			lines4, alive4 = runStreamingFRRScan(cctx, vtyshBin, vtyBaseArgs, cmd4, "ipv4", maxV4)
		}()
		go func() {
			defer wg.Done()
			cmd6 := fmt.Sprintf("show bgp %sipv6 unicast %s json", clause, filterClause)
			lines6, alive6 = runStreamingFRRScan(cctx, vtyshBin, vtyBaseArgs, cmd6, "ipv6", maxV6)
		}()
		wg.Wait()

		matchedAnyScope := alive4 || alive6
		if matchedAnyScope {
			vtyshAlive = true
		}

		total := len(lines4) + len(lines6)
		if total > 0 {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("# Node: %s | Engine: FRR | VRF: %s | Filter: %s\n",
				rrNode.Name, vrfName, target))
			if len(lines4) > 0 {
				sb.WriteString(fmt.Sprintf("\n--- IPv4 Unicast (%d routes) ---\n", len(lines4)))
				sb.WriteString(fmt.Sprintf("   %-22s %-16s %-6s %-6s %s\n", "Network", "Next Hop", "LocPrf", "MED", "AS_PATH"))
				for _, line := range lines4 {
					sb.WriteString(line + "\n")
				}
			}
			if len(lines6) > 0 {
				sb.WriteString(fmt.Sprintf("\n--- IPv6 Unicast (%d routes) ---\n", len(lines6)))
				sb.WriteString(fmt.Sprintf("   %-36s %-32s %-6s %-6s %s\n", "Network", "Next Hop", "LocPrf", "MED", "AS_PATH"))
				for _, line := range lines6 {
					sb.WriteString(line + "\n")
				}
			}
			return total, formatDualStackFilterSummary(target, len(lines4), len(lines6)), sb.String(), true
		}
		if matchedAnyScope {
			emptyRaw := fmt.Sprintf("# Node: %s | Engine: FRR\n# VRF: %s | Filter: %s\nNetwork not in table.\n",
				rrNode.Name, vrfName, target)
			return 0, "No matching route", emptyRaw, true
		}
	}

	if vtyshAlive {
		emptyRaw := fmt.Sprintf("# Node: %s | Engine: FRR\n# VRF: %s | Target: %s\nNetwork not in table.\n",
			rrNode.Name, vrfName, target)
		return 0, "No matching route", emptyRaw, true
	}
	return 0, "", "", false
}

func (e *Engine) queryLiveFrrNeighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgentNeighbors(ctx, rrNode, "frr", views)
	}
	return e.RunLocalFrrNeighbors(ctx, rrNode, views)
}

// RunLocalFrrNeighbors queries `vtysh -c "show bgp [view|vrf <VRF>] summary json"` and `neighbors json` per bound VRF.
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

	if _, err := runVtysh(cctx, vtyshBin, vtyBaseArgs, "show bgp summary json"); err != nil {
		return nil, false
	}

	summaries := make([]models.BGPNeighborSummary, 0, len(views))
	for _, v := range views {
		vrfName := resolveVRFName(v)
		clauses := frrScopeClauses(vrfName)
		hintIP := strings.TrimSpace(v.JuniperSourceIPv4)

		type aggPeer struct {
			ip               string
			asn              uint32
			localAS          uint32
			state            string
			uptime           string
			v4               int
			v6               int
			msgRcvd          int64
			addPathRx        bool
			nextHopUnchanged bool
		}
		peerMap := make(map[string]*aggPeer)

		for _, clause := range clauses {
			cmdStr := fmt.Sprintf("show bgp %ssummary json", clause)
			outBytes, err := runVtysh(cctx, vtyshBin, vtyBaseArgs, cmdStr)
			if err != nil || frrOutputIsScopeError(string(outBytes)) {
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
					localAS := p.LocalAS
					if localAS == 0 {
						localAS = af.AS
					}
					ap, exists := peerMap[ip]
					if !exists {
						ap = &aggPeer{
							ip:               ip,
							asn:              p.RemoteAS,
							localAS:          localAS,
							state:            p.State,
							uptime:           p.PeerUptime,
							nextHopUnchanged: localAS > 0 && localAS == p.RemoteAS,
						}
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
				// Inspect negotiated capabilities (`neighbors json`) for real Add-Path RX & iBGP type
				if nbrBytes, errNbr := runVtysh(cctx, vtyshBin, vtyBaseArgs, fmt.Sprintf("show bgp %sneighbors json", clause)); errNbr == nil {
					var nbrMap map[string]frrNeighborDetailJSON
					if json.Unmarshal(nbrBytes, &nbrMap) == nil {
						for ip, ap := range peerMap {
							if detail, has := nbrMap[ip]; has {
								if strings.EqualFold(detail.BgpType, "internal") || (detail.LocalAs > 0 && detail.LocalAs == detail.RemoteAs) {
									ap.nextHopUnchanged = true
								}
								if detail.NeighborCapabilities != nil {
									for _, capAF := range detail.NeighborCapabilities.AddPath {
										if capAF.RxAdvertisedAndReceived || capAF.RxAdvertised || capAF.RxReceived {
											ap.addPathRx = true
										}
									}
								}
							}
						}
					}
				}
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
				AddPathRx:        ap.addPathRx,
				NextHopUnchanged: ap.nextHopUnchanged,
				PrefixesIPv4:     ap.v4,
				PrefixesIPv6:     ap.v6,
				UpdatesReceived:  ap.msgRcvd,
			})
		}
	}

	return summaries, true
}
