// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

func (e *Engine) queryLiveBird2VRF(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) (int, string, string, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgent(ctx, rrNode, "bird2", view, queryType, target)
	}
	return e.RunLocalBird2Query(ctx, rrNode, view, queryType, target)
}

func (e *Engine) RunLocalBird2Query(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) (int, string, string, bool) {
	maxV4, maxV6 := e.filterRouteLimits()
	return e.RunLocalBird2QueryWithLimits(ctx, rrNode, view, queryType, target, maxV4, maxV6)
}

// bird2CandidateTables returns ordered safe BIRD 2 table names for a given address family ("ipv4" or "ipv6").
// Because BIRD 2 strictly separates IPv4 and IPv6 routing tables (e.g. 'LSYS-OPT' and 'LSYS-OPT-v6'),
// Multi-VRF IPv6 lookups try explicit BirdTableV6 first, followed by common '-v6' / '_v6' / '6' conventions.
func bird2CandidateTables(view models.RouteViewMeta, vrfName string, fam string) []string {
	var rawCandidates []string
	if isGlobalRIB(vrfName) {
		if fam == "ipv6" {
			if t6 := strings.TrimSpace(view.BirdTableV6); t6 != "" && !strings.EqualFold(t6, "global") {
				rawCandidates = append(rawCandidates, t6)
			}
			rawCandidates = append(rawCandidates, "master6")
		} else {
			if t4 := strings.TrimSpace(view.BirdTableV4); t4 != "" && !strings.EqualFold(t4, "global") {
				rawCandidates = append(rawCandidates, t4)
			}
			rawCandidates = append(rawCandidates, "master4")
		}
	} else {
		if fam == "ipv6" {
			if t6 := strings.TrimSpace(view.BirdTableV6); t6 != "" {
				rawCandidates = append(rawCandidates, t6)
			}
			rawCandidates = append(rawCandidates,
				vrfName+"-v6",
				vrfName+"_v6",
				vrfName+"6",
				vrfName,
			)
		} else {
			if t4 := strings.TrimSpace(view.BirdTableV4); t4 != "" {
				rawCandidates = append(rawCandidates, t4)
			}
			rawCandidates = append(rawCandidates,
				vrfName,
				vrfName+"-v4",
				vrfName+"_v4",
			)
		}
	}

	var safe []string
	seen := make(map[string]bool)
	for _, c := range rawCandidates {
		c = strings.TrimSpace(c)
		if c == "" || !reSafeVRFName.MatchString(c) {
			continue
		}
		key := strings.ToLower(c)
		if !seen[key] {
			seen[key] = true
			safe = append(safe, c)
		}
	}
	return safe
}

func isBird2ErrorOutput(rawOut string) bool {
	lower := strings.ToLower(rawOut)
	return strings.Contains(lower, "syntax error") ||
		strings.Contains(lower, "unable to connect") ||
		strings.Contains(lower, "no such table") ||
		strings.Contains(lower, "symbol not known") ||
		strings.Contains(lower, "net type mismatch") ||
		strings.Contains(lower, "table type mismatch")
}

// RunLocalBird2QueryWithLimits executes a read-only `birdc -r` query locally with explicit IPv4/IPv6 route caps.
func (e *Engine) RunLocalBird2QueryWithLimits(
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
	birdcBin, err := exec.LookPath("birdc")
	if err != nil {
		return 0, "", "", false
	}

	vrfName := resolveVRFName(view)
	timeout := 5 * time.Second
	if queryType == "aspath" || queryType == "community" {
		timeout = 25 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var birdArgs []string
	sock := strings.TrimSpace(rrNode.Endpoint)
	if sock != "" && !strings.EqualFold(sock, "local") && !strings.Contains(sock, ":") {
		birdArgs = append(birdArgs, "-s", sock)
	}

	runBirdCmd := func(command string) (string, bool, bool) {
		args := append(append([]string{}, birdArgs...), "-r", command)
		outBytes, err := exec.CommandContext(cctx, birdcBin, args...).Output()
		if err != nil && len(outBytes) == 0 {
			return "", false, false
		}
		rawOut := string(outBytes)
		if strings.Contains(strings.ToLower(rawOut), "unable to connect") {
			return "", false, false
		}
		if isBird2ErrorOutput(rawOut) {
			// Daemon is alive, but table name or net-type did not match
			return rawOut, false, true
		}
		return rawOut, true, true
	}

	// Mode 1: IPv4 / IPv6 Prefix or IP lookup (strictly targets matching address-family BIRD table)
	if queryType == "prefix" {
		normalized, fam, _, errVal := security.ValidatePrefixOrIP(target)
		if errVal != nil {
			return 0, "", "", false
		}
		candidates := bird2CandidateTables(view, vrfName, fam)
		if len(candidates) == 0 {
			return 0, "", "", false
		}

		daemonAlive := false
		for _, tbl := range candidates {
			cmd := fmt.Sprintf("show route table '%s' for %s all", tbl, normalized)
			rawOut, ok, alive := runBirdCmd(cmd)
			if alive {
				daemonAlive = true
			}
			if !ok {
				continue
			}
			if strings.Contains(rawOut, "Network not in table") {
				return 0, "No matching route", rawOut, true
			}
			count, matched, clippedRaw := clipAndCountBird2Output(rawOut, target, 0, 0)
			if count == 0 {
				return 0, "No matching route", rawOut, true
			}
			return count, matched, clippedRaw, true
		}

		if daemonAlive {
			emptyRaw := fmt.Sprintf("# Node: %s | Engine: BIRD2\n# VRF: %s (%s) | Target: %s\nNetwork not in table.\n",
				rrNode.Name, vrfName, strings.ToUpper(fam), normalized)
			return 0, "No matching route", emptyRaw, true
		}
		return 0, "", "", false
	}

	// Mode 2 & 3: AS-Path (with ^ / $ anchors) or Community / Large-Community filter scan across IPv4 & IPv6 tables
	var whereClause string
	switch queryType {
	case "aspath":
		cleaned, errVal := security.ValidateASPathOrASN(target)
		if errVal != nil {
			return 0, "", "", false
		}
		pattern := BuildBird2ASPathPattern(cleaned)
		if pattern == "" {
			return 0, "", "", false
		}
		whereClause = fmt.Sprintf("where bgp_path ~ %s all", pattern)
	case "community":
		cleaned, errVal := security.ValidateCommunity(target)
		if errVal != nil {
			return 0, "", "", false
		}
		if wk, ok := wellKnownCommunityTuple(cleaned); ok {
			whereClause = fmt.Sprintf("where %s ~ bgp_community all", wk)
		} else {
			parts := strings.Split(cleaned, ":")
			switch len(parts) {
			case 2:
				whereClause = fmt.Sprintf("where (%s, %s) ~ bgp_community all", parts[0], parts[1])
			case 3:
				whereClause = fmt.Sprintf("where (%s, %s, %s) ~ bgp_large_community all", parts[0], parts[1], parts[2])
			default:
				return 0, "", "", false
			}
		}
	default:
		return 0, "", "", false
	}

	v4Candidates := bird2CandidateTables(view, vrfName, "ipv4")
	v6Candidates := bird2CandidateTables(view, vrfName, "ipv6")
	// Prevent querying the exact same table twice if BirdTableV6 was manually set equal to BirdTableV4
	var dedupV6 []string
	for _, t6 := range v6Candidates {
		if len(v4Candidates) > 0 && strings.EqualFold(t6, v4Candidates[0]) {
			continue
		}
		dedupV6 = append(dedupV6, t6)
	}

	queryFirstValidTable := func(tables []string) (string, bool, bool) {
		anyAlive := false
		for _, tbl := range tables {
			raw, ok, alive := runBirdCmd(fmt.Sprintf("show route table '%s' %s", tbl, whereClause))
			if alive {
				anyAlive = true
			}
			if ok {
				return raw, true, true
			}
		}
		return "", false, anyAlive
	}

	var (
		wg               sync.WaitGroup
		raw4, raw6       string
		ok4, ok6         bool
		alive4, alive6   bool
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		raw4, ok4, alive4 = queryFirstValidTable(v4Candidates)
	}()
	go func() {
		defer wg.Done()
		raw6, ok6, alive6 = queryFirstValidTable(dedupV6)
	}()
	wg.Wait()

	if !ok4 && !ok6 && !alive4 && !alive6 {
		return 0, "", "", false
	}

	var count4, count6 int
	var clip4, clip6 string
	if ok4 && !strings.Contains(raw4, "Network not in table") {
		count4, _, clip4 = clipAndCountBird2Output(raw4, target, maxV4, 0)
	}
	if ok6 && !strings.Contains(raw6, "Network not in table") {
		count6, _, clip6 = clipAndCountBird2Output(raw6, target, 0, maxV6)
	}

	total := count4 + count6
	if total == 0 {
		emptyRaw := fmt.Sprintf("# Node: %s | Engine: BIRD2\n# VRF: %s | Filter: %s\nNetwork not in table.\n",
			rrNode.Name, vrfName, target)
		return 0, "No matching route", emptyRaw, true
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Node: %s | Engine: BIRD2 | VRF: %s | Filter: %s\n",
		rrNode.Name, vrfName, target))
	if count4 > 0 {
		sb.WriteString(fmt.Sprintf("\n--- IPv4 Routes (%d matched) ---\n", count4))
		sb.WriteString(clip4)
		if !strings.HasSuffix(clip4, "\n") {
			sb.WriteString("\n")
		}
	}
	if count6 > 0 {
		sb.WriteString(fmt.Sprintf("\n--- IPv6 Routes (%d matched) ---\n", count6))
		sb.WriteString(clip6)
		if !strings.HasSuffix(clip6, "\n") {
			sb.WriteString("\n")
		}
	}
	return total, formatDualStackFilterSummary(target, count4, count6), sb.String(), true
}

// clipAndCountBird2Output counts matched routes in native `birdc` text output and enforces IPv4/IPv6 route limits.
func clipAndCountBird2Output(rawOut string, target string, maxV4, maxV6 int) (int, string, string) {
	lines := strings.Split(rawOut, "\n")
	var matchedPrefix string
	var curFam string
	var curLines []string
	var keptLines []string
	hasCur := false
	v4Count, v6Count := 0, 0
	truncated := false

	flush := func() {
		if !hasCur {
			return
		}
		withinLimit := (curFam == "ipv6" && (maxV6 <= 0 || v6Count < maxV6)) ||
			(curFam != "ipv6" && (maxV4 <= 0 || v4Count < maxV4))
		if withinLimit {
			keptLines = append(keptLines, curLines...)
			if curFam == "ipv6" {
				v6Count++
			} else {
				v4Count++
			}
		} else {
			truncated = true
		}
		hasCur = false
		curLines = nil
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "BIRD ") || strings.HasPrefix(line, "Table ") {
			continue
		}
		isHeader := !strings.HasPrefix(rawLine, "\t") && !strings.HasPrefix(rawLine, " ") && (strings.Contains(line, "unicast") || strings.Contains(line, " ["))
		if isHeader {
			flush()
			if (maxV4 > 0 && v4Count >= maxV4) && (maxV6 > 0 && v6Count >= maxV6) {
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
			fam := "ipv4"
			if strings.Contains(matchedPrefix, ":") {
				fam = "ipv6"
			}
			if (fam == "ipv6" && maxV6 > 0 && v6Count >= maxV6) || (fam != "ipv6" && maxV4 > 0 && v4Count >= maxV4) {
				truncated = true
				continue
			}
			curFam = fam
			hasCur = true
			curLines = []string{rawLine}
			continue
		}
		if hasCur {
			curLines = append(curLines, rawLine)
		}
	}
	flush()

	total := v4Count + v6Count
	if matchedPrefix == "" {
		matchedPrefix = "No matching route"
	}
	outRaw := rawOut
	if truncated && len(keptLines) > 0 {
		outRaw = strings.Join(keptLines, "\n") + fmt.Sprintf("\n# ... truncated after configured route limits (IPv4=%d, IPv6=%d) ...\n", maxV4, maxV6)
	}
	return total, matchedPrefix, outRaw
}

type birdProtocolInfo struct {
	name             string
	state            string
	since            string
	neighborIP       string
	neighborAS       uint32
	localAS          uint32
	tables           []string
	ipv4Routes       int
	ipv6Routes       int
	updatesReceived  int64
	addPathRx        bool
	nextHopUnchanged bool
}

func (e *Engine) queryLiveBird2Neighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	if IsRemoteAgentEndpoint(rrNode.Endpoint) {
		return e.queryRemoteAgentNeighbors(ctx, rrNode, "bird2", views)
	}
	return e.RunLocalBird2Neighbors(ctx, rrNode, views)
}

func birdTableMatchesView(tbl string, v models.RouteViewMeta, vrfName string) bool {
	if isGlobalRIB(vrfName) {
		return isGlobalRIB(tbl)
	}
	candidates := []string{
		vrfName,
		strings.TrimSpace(v.BirdTableV4),
		strings.TrimSpace(v.BirdTableV6),
		vrfName + "-v4",
		vrfName + "_v4",
		vrfName + "-v6",
		vrfName + "_v6",
		vrfName + "4",
		vrfName + "6",
	}
	for _, c := range candidates {
		if c != "" && strings.EqualFold(tbl, c) {
			return true
		}
	}
	return false
}

// RunLocalBird2Neighbors queries `birdc -r "show protocols all"` and maps BGP sessions + live capabilities strictly to each bound VRF.
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
	if strings.Contains(strings.ToLower(raw), "unable to connect") {
		return nil, false
	}

	var protos []birdProtocolInfo
	var cur *birdProtocolInfo
	curChan := ""

	flushProto := func() {
		if cur != nil {
			if cur.localAS > 0 && cur.localAS == cur.neighborAS {
				cur.nextHopUnchanged = true
			}
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
		lowerTrimmed := strings.ToLower(trimmed)
		if strings.HasPrefix(trimmed, "BGP state:") {
			cur.state = strings.TrimSpace(strings.TrimPrefix(trimmed, "BGP state:"))
		} else if strings.HasPrefix(trimmed, "Neighbor address:") {
			cur.neighborIP = strings.TrimSpace(strings.TrimPrefix(trimmed, "Neighbor address:"))
		} else if strings.HasPrefix(trimmed, "Neighbor AS:") {
			if n, errConv := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(trimmed, "Neighbor AS:")), 10, 32); errConv == nil {
				cur.neighborAS = uint32(n)
			}
		} else if strings.HasPrefix(trimmed, "Local AS:") {
			if n, errConv := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(trimmed, "Local AS:")), 10, 32); errConv == nil {
				cur.localAS = uint32(n)
			}
		} else if strings.Contains(lowerTrimmed, "internal bgp") {
			cur.nextHopUnchanged = true
		} else if strings.HasPrefix(lowerTrimmed, "add-path:") || strings.HasPrefix(lowerTrimmed, "add paths:") {
			if strings.Contains(lowerTrimmed, "rx") || strings.Contains(lowerTrimmed, "both") || strings.Contains(lowerTrimmed, "on") {
				cur.addPathRx = true
			}
		} else if strings.HasPrefix(trimmed, "Channel ") {
			curChan = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "Channel ")))
		} else if strings.HasPrefix(trimmed, "Table:") {
			tbl := strings.TrimSpace(strings.TrimPrefix(trimmed, "Table:"))
			cur.tables = append(cur.tables, tbl)
		} else if strings.HasPrefix(trimmed, "Routes:") {
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
		} else if strings.HasPrefix(trimmed, "Import updates:") {
			// Format: "Import updates:     1369039          0          0          0          0"
			fields := strings.Fields(strings.TrimPrefix(trimmed, "Import updates:"))
			if len(fields) > 0 {
				if rx, errConv := strconv.ParseInt(fields[0], 10, 64); errConv == nil {
					cur.updatesReceived += rx
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
				if birdTableMatchesView(tbl, v, vrfName) {
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
			updates := p.updatesReceived
			if updates == 0 {
				updates = int64(p.ipv4Routes + p.ipv6Routes)
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
				AddPathRx:        p.addPathRx,
				NextHopUnchanged: p.nextHopUnchanged,
				PrefixesIPv4:     p.ipv4Routes,
				PrefixesIPv6:     p.ipv6Routes,
				UpdatesReceived:  updates,
			})
		}
	}

	return summaries, true
}
