// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

// queryLiveGoBGPgRPC queries GoBGP directly over native gRPC (ListVrf + ListPath RPC) without CLI execution.
// Enforces strict VRF isolation: when a specific VRF is requested, it NEVER falls back to the Global Unicast RIB.
func (e *Engine) queryLiveGoBGPgRPC(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) (int, string, string, bool) {
	client, err := defaultPool.getClient(rrNode.Endpoint)
	if err != nil {
		return 0, "", "", false
	}

	timeout := 5 * time.Second
	if queryType == "aspath" || queryType == "community" {
		timeout = 25 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	familyStr := "ipv4"
	var lookupCIDR string
	var isExactPrefix bool

	if queryType == "prefix" {
		normalized, fam, isPrefix, errVal := security.ValidatePrefixOrIP(target)
		if errVal != nil {
			return 0, "", "", false
		}
		familyStr = fam
		isExactPrefix = isPrefix
		if isPrefix {
			lookupCIDR = normalized
		} else if fam == "ipv6" {
			lookupCIDR = normalized + "/128"
		} else {
			lookupCIDR = normalized + "/32"
		}
	} else if strings.Contains(target, ":") && strings.Count(target, ":") > 2 {
		familyStr = "ipv6"
	}

	afi := apipb.Family_AFI_IP
	neighborIP := strings.TrimSpace(view.JuniperSourceIPv4)
	if familyStr == "ipv6" {
		afi = apipb.Family_AFI_IP6
		if strings.TrimSpace(view.JuniperSourceIPv6) != "" {
			neighborIP = strings.TrimSpace(view.JuniperSourceIPv6)
		}
	}

	vrfName := resolveVRFName(view)
	wantGlobal := isGlobalRIB(vrfName)
	rdStr, grpcAlive := e.resolveGoBGPVrfRD(cctx, client, rrNode.Endpoint, vrfName)
	if !grpcAlive {
		return 0, "", "", false
	}

	maxV4, maxV6 := e.filterRouteLimits()

	runLookup := func(targetAFI apipb.Family_Afi, famLabel string, tableType apipb.TableType, tableName string, safi apipb.Family_Safi, rd string, lType apipb.TableLookupPrefix_Type) (int, string, string, bool) {
		var prefixes []*apipb.TableLookupPrefix
		batchSize := uint64(0)
		sortType := apipb.ListPathRequest_PREFIX
		onlyBinary := false
		maxMatches := maxV4
		if famLabel == "ipv6" {
			maxMatches = maxV6
		}

		if queryType == "prefix" && lookupCIDR != "" {
			prefixes = []*apipb.TableLookupPrefix{
				{
					Prefix: lookupCIDR,
					Rd:     rd,
					Type:   lType,
				},
			}
		} else {
			batchSize = 64
			sortType = apipb.ListPathRequest_NONE
			onlyBinary = true
		}
		req := &apipb.ListPathRequest{
			TableType: tableType,
			Name:      tableName,
			Family: &apipb.Family{
				Afi:  targetAFI,
				Safi: safi,
			},
			Prefixes:         prefixes,
			SortType:         sortType,
			BatchSize:        batchSize,
			EnableOnlyBinary: onlyBinary,
		}
		return e.fetchPathsFromStream(cctx, client, req, famLabel, queryType, target, rd, maxMatches)
	}

	runDualStackFilter := func(safi apipb.Family_Safi, rd string) (int, string, string, bool) {
		var (
			wg      sync.WaitGroup
			v4Count int
			v6Count int
			v4Raw   string
			v6Raw   string
			v4OK    bool
			v6OK    bool
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			v4Count, _, v4Raw, v4OK = runLookup(apipb.Family_AFI_IP, "ipv4", apipb.TableType_GLOBAL, "", safi, rd, apipb.TableLookupPrefix_SHORTER)
		}()
		go func() {
			defer wg.Done()
			v6Count, _, v6Raw, v6OK = runLookup(apipb.Family_AFI_IP6, "ipv6", apipb.TableType_GLOBAL, "", safi, rd, apipb.TableLookupPrefix_SHORTER)
		}()
		wg.Wait()

		if !v4OK && !v6OK {
			return 0, "", "", false
		}
		total := v4Count + v6Count
		if total == 0 {
			emptyRaw := fmt.Sprintf("# Node: %s | Engine: GOBGP\n# VRF: %s | Target: %s\nNetwork not in table.\n",
				rrNode.Name, vrfName, target)
			return 0, "No matching route", emptyRaw, true
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# Node: %s | Engine: GOBGP | VRF: %s | Filter: %s\n",
			rrNode.Name, vrfName, target))
		if v4Count > 0 {
			sb.WriteString(fmt.Sprintf("\n--- IPv4 Routes (%d matched) ---\n", v4Count))
			sb.WriteString(v4Raw)
		}
		if v6Count > 0 {
			sb.WriteString(fmt.Sprintf("\n--- IPv6 Routes (%d matched) ---\n", v6Count))
			sb.WriteString(v6Raw)
		}
		return total, formatDualStackFilterSummary(target, v4Count, v6Count), sb.String(), true
	}

	// Case 1: Dedicated Multi-VRF Mode (`!wantGlobal`) — STRICT VRF ISOLATION (never falls back to Global Unicast RIB!)
	if !wantGlobal {
		if rdStr != "" {
			if queryType != "prefix" {
				count, matched, rawOut, ok := runDualStackFilter(apipb.Family_SAFI_MPLS_VPN, rdStr)
				if !ok {
					InvalidateVRFRDCache()
					return 0, "", "", false
				}
				return count, matched, rawOut, true
			}
			rpcAlive := false
			if isExactPrefix {
				count, matched, rawOut, ok := runLookup(afi, familyStr, apipb.TableType_GLOBAL, "", apipb.Family_SAFI_MPLS_VPN, rdStr, apipb.TableLookupPrefix_EXACT)
				if ok {
					rpcAlive = true
					if count > 0 {
						return count, matched, rawOut, true
					}
				}
			}
			count, matched, rawOut, ok := runLookup(afi, familyStr, apipb.TableType_GLOBAL, "", apipb.Family_SAFI_MPLS_VPN, rdStr, apipb.TableLookupPrefix_SHORTER)
			if ok {
				rpcAlive = true
				if count > 0 {
					return count, matched, rawOut, true
				}
			}
			if !rpcAlive {
				InvalidateVRFRDCache()
				return 0, "", "", false
			}
			emptyRaw := fmt.Sprintf("# Node: %s | Engine: GOBGP\n# VRF: %s (RD %s) | Target: %s\nNetwork not in table.\n",
				rrNode.Name, vrfName, rdStr, target)
			return 0, "No matching route", emptyRaw, true
		}

		// VRF has no MPLS VPN RD on this GoBGP collector: only check dedicated VRF neighbor Adj-RIB-In if explicitly configured
		if queryType == "prefix" && neighborIP != "" {
			count, matched, rawOut, ok := runLookup(afi, familyStr, apipb.TableType_ADJ_IN, neighborIP, apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_SHORTER)
			if !ok {
				return 0, "", "", false
			}
			if count > 0 {
				return count, matched, rawOut, true
			}
		}

		emptyRaw := fmt.Sprintf("# Node: %s | Engine: GOBGP\n# VRF: %s | Target: %s\nNetwork not in table (VRF %s has no matching routes on this RR).\n",
			rrNode.Name, vrfName, target, vrfName)
		return 0, "No matching route", emptyRaw, true
	}

	// Case 2: Single Global Unicast RIB (`wantGlobal == true`)
	if queryType != "prefix" {
		return runDualStackFilter(apipb.Family_SAFI_UNICAST, "")
	}

	rpcAlive := false
	if isExactPrefix {
		count, matched, rawOut, ok := runLookup(afi, familyStr, apipb.TableType_GLOBAL, "", apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_EXACT)
		if ok {
			rpcAlive = true
			if count > 0 {
				return count, matched, rawOut, true
			}
		}
	}
	count, matched, rawOut, ok := runLookup(afi, familyStr, apipb.TableType_GLOBAL, "", apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_SHORTER)
	if ok {
		rpcAlive = true
		if count > 0 {
			return count, matched, rawOut, true
		}
	}

	if neighborIP != "" {
		adjCount, adjMatched, adjRaw, adjOK := runLookup(afi, familyStr, apipb.TableType_ADJ_IN, neighborIP, apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_SHORTER)
		if adjOK {
			rpcAlive = true
			if adjCount > 0 {
				return adjCount, adjMatched, adjRaw, true
			}
		}
	}

	if !rpcAlive {
		return 0, "", "", false
	}

	emptyRaw := fmt.Sprintf("# Node: %s | Engine: GOBGP\n# VRF: %s | Target: %s\nNetwork not in table.\n",
		rrNode.Name, vrfName, target)
	return 0, "No matching route", emptyRaw, true
}

func stripRDFromPrefix(prefixStr string, rd string) string {
	if rd != "" && strings.HasPrefix(prefixStr, rd+":") {
		return strings.TrimPrefix(prefixStr, rd+":")
	}
	return prefixStr
}

func maskLengthOfPrefix(prefixStr string, rd string) int {
	clean := stripRDFromPrefix(prefixStr, rd)
	if idx := strings.LastIndex(clean, "/"); idx != -1 {
		var l int
		if _, err := fmt.Sscanf(clean[idx+1:], "%d", &l); err == nil {
			return l
		}
	}
	return -1
}

func writeGoBGPCLIHeader(sb *strings.Builder, familyStr string) {
	if familyStr == "ipv6" {
		sb.WriteString(fmt.Sprintf("   %-32s %-30s %-6s %-6s %-9s %-24s %s\n",
			"Network", "Next Hop", "LocPrf", "MED", "Age", "AS_PATH", "Attrs"))
	} else {
		sb.WriteString(fmt.Sprintf("   %-20s %-16s %-6s %-6s %-9s %-24s %s\n",
			"Network", "Next Hop", "LocPrf", "MED", "Age", "AS_PATH", "Attrs"))
	}
}

func matchesCommunityList(comms, extComms []string, rawLine, rawQuery string) bool {
	want := strings.TrimSpace(rawQuery)
	if want == "" {
		return false
	}
	for _, c := range comms {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	for _, ec := range extComms {
		if strings.EqualFold(ec, want) || strings.Contains(strings.ToLower(ec), strings.ToLower(want)) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(rawLine), strings.ToLower(want))
}

func fastMatchBinaryPath(pattrsBin [][]byte, queryType string, rawQuery string) bool {
	if len(pattrsBin) == 0 {
		return true
	}
	if queryType == "aspath" {
		parsedQ, ok := ParseASPathQuery(rawQuery)
		if !ok {
			return false
		}
		for _, attrBytes := range pattrsBin {
			if len(attrBytes) < 2 || bgp.BGPAttrType(attrBytes[1]) != bgp.BGP_ATTR_TYPE_AS_PATH {
				continue
			}
			a, err := bgp.GetPathAttribute(attrBytes)
			if err != nil {
				continue
			}
			if err := a.DecodeFromBytes(attrBytes); err != nil {
				continue
			}
			asAttr, ok := a.(*bgp.PathAttributeAsPath)
			if !ok {
				continue
			}
			var routeASNs []uint32
			for _, param := range asAttr.Value {
				switch seg := param.(type) {
				case *bgp.As4PathParam:
					routeASNs = append(routeASNs, seg.AS...)
				case *bgp.AsPathParam:
					for _, asn := range seg.AS {
						routeASNs = append(routeASNs, uint32(asn))
					}
				}
			}
			if MatchASSequence(routeASNs, parsedQ) {
				return true
			}
		}
		return false
	}

	if queryType == "community" {
		want := strings.TrimSpace(rawQuery)
		if want == "" {
			return false
		}
		wantLower := strings.ToLower(want)
		var hasStdTarget bool
		var stdTarget uint32
		if parts := strings.Split(want, ":"); len(parts) == 2 {
			var h, l uint32
			if _, err1 := fmt.Sscanf(parts[0], "%d", &h); err1 == nil && h <= 65535 {
				if _, err2 := fmt.Sscanf(parts[1], "%d", &l); err2 == nil && l <= 65535 {
					stdTarget = (h << 16) | l
					hasStdTarget = true
				}
			}
		}

		for _, attrBytes := range pattrsBin {
			if len(attrBytes) < 2 {
				continue
			}
			tCode := bgp.BGPAttrType(attrBytes[1])
			if tCode != bgp.BGP_ATTR_TYPE_COMMUNITIES &&
				tCode != bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES &&
				tCode != bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY {
				continue
			}
			a, err := bgp.GetPathAttribute(attrBytes)
			if err != nil {
				continue
			}
			if err := a.DecodeFromBytes(attrBytes); err != nil {
				continue
			}
			switch ca := a.(type) {
			case *bgp.PathAttributeCommunities:
				if hasStdTarget {
					for _, c := range ca.Value {
						if c == stdTarget {
							return true
						}
					}
				}
				if strings.Contains(strings.ToLower(ca.String()), wantLower) {
					return true
				}
			case *bgp.PathAttributeExtendedCommunities:
				if strings.Contains(strings.ToLower(ca.String()), wantLower) {
					return true
				}
			case *bgp.PathAttributeLargeCommunities:
				if strings.Contains(strings.ToLower(ca.String()), wantLower) {
					return true
				}
			}
		}
		return false
	}
	return true
}

func (e *Engine) fetchPathsFromStream(
	ctx context.Context,
	client apipb.GobgpApiClient,
	req *apipb.ListPathRequest,
	familyStr string,
	queryType string,
	target string,
	rd string,
	maxFilterMatches int,
) (int, string, string, bool) {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream, err := client.ListPath(streamCtx, req)
	if err != nil {
		return 0, "", "", false
	}

	// Mode A: Stream-filter on-the-fly for AS-Path or Community queries
	if queryType == "aspath" || queryType == "community" {
		maxFilterMatches = clampFilterRouteLimit(maxFilterMatches)
		var parsedASQuery ASPathQuery
		if queryType == "aspath" {
			var ok bool
			parsedASQuery, ok = ParseASPathQuery(target)
			if !ok {
				return 0, "", "", false
			}
		}

		var rawLines []string
		receivedAny := false

		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				if receivedAny || len(rawLines) > 0 {
					break
				}
				return 0, "", "", false
			}
			receivedAny = true
			dest := resp.GetDestination()
			if dest == nil || len(dest.GetPaths()) == 0 {
				continue
			}
			if rd != "" && !strings.HasPrefix(dest.GetPrefix(), rd+":") {
				continue
			}

			cleanPfx := stripRDFromPrefix(dest.GetPrefix(), rd)
			for idx, p := range dest.GetPaths() {
				if len(p.GetPattrsBinary()) > 0 && !fastMatchBinaryPath(p.GetPattrsBinary(), queryType, target) {
					continue
				}
				rawLine, asns, comms, extComms := decodeGoBGPPathLine(idx == 0, cleanPfx, rd, familyStr, p)
				if queryType == "aspath" {
					if !MatchASSequence(asns, parsedASQuery) {
						continue
					}
				} else if queryType == "community" {
					if !matchesCommunityList(comms, extComms, rawLine, target) {
						continue
					}
				}
				rawLines = append(rawLines, rawLine)
				if len(rawLines) >= maxFilterMatches {
					cancelStream()
					break
				}
			}
			if len(rawLines) >= maxFilterMatches {
				break
			}
		}

		if len(rawLines) == 0 {
			return 0, "", "", true
		}

		var rawBuilder strings.Builder
		writeGoBGPCLIHeader(&rawBuilder, familyStr)
		for _, line := range rawLines {
			rawBuilder.WriteString(line + "\n")
		}
		summaryLabel := fmt.Sprintf("Filter: %s (%d routes)", target, len(rawLines))
		return len(rawLines), summaryLabel, rawBuilder.String(), true
	}

	// Mode B: Prefix lookup (O(1) radix/hash lookup with Longest Prefix Match selection)
	var allDests []*apipb.Destination
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, "", "", false
		}
		dest := resp.GetDestination()
		if dest == nil || len(dest.GetPaths()) == 0 {
			continue
		}
		if rd != "" && !strings.HasPrefix(dest.GetPrefix(), rd+":") {
			continue
		}
		allDests = append(allDests, dest)
	}

	if len(allDests) == 0 {
		return 0, "", "", true
	}

	selectedDests := allDests
	if len(allDests) > 1 {
		bestMask := maskLengthOfPrefix(allDests[0].GetPrefix(), rd)
		for _, d := range allDests[1:] {
			if m := maskLengthOfPrefix(d.GetPrefix(), rd); m > bestMask {
				bestMask = m
			}
		}
		var longest []*apipb.Destination
		for _, d := range allDests {
			if maskLengthOfPrefix(d.GetPrefix(), rd) == bestMask {
				longest = append(longest, d)
			}
		}
		if len(longest) > 0 {
			selectedDests = longest
		}
	}

	var rawLines []string
	var matchedPrefix string
	for _, dest := range selectedDests {
		cleanPfx := stripRDFromPrefix(dest.GetPrefix(), rd)
		if matchedPrefix == "" {
			matchedPrefix = cleanPfx
		}
		for idx, p := range dest.GetPaths() {
			rawLine, _, _, _ := decodeGoBGPPathLine(idx == 0, cleanPfx, rd, familyStr, p)
			rawLines = append(rawLines, rawLine)
		}
	}

	var rawBuilder strings.Builder
	writeGoBGPCLIHeader(&rawBuilder, familyStr)
	for _, line := range rawLines {
		rawBuilder.WriteString(line + "\n")
	}

	return len(rawLines), matchedPrefix, rawBuilder.String(), true
}

func formatGoBGPTimedelta(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "00:00:00"
	}
	d := time.Now().Unix() - t.Unix()
	if d < 0 {
		d = -d
	}
	u := uint64(d)
	secs := u % 60
	u /= 60
	mins := u % 60
	u /= 60
	hours := u % 24
	days := u / 24

	if days == 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	}
	return fmt.Sprintf("%dd %02d:%02d:%02d", days, hours, mins, secs)
}

func getNativeNextHop(attrs []bgp.PathAttributeInterface) net.IP {
	for _, attr := range attrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			return a.Value
		case *bgp.PathAttributeMpReachNLRI:
			return a.Nexthop
		}
	}
	return nil
}

func formatFullWidthPathLine(leftCols string, stdComms, extComms, largeComms []string, rpkiTag string) string {
	var tokens []string
	if rpkiTag != "" {
		tokens = append(tokens, "{RPKI: "+rpkiTag+"}")
	}
	if len(stdComms) > 0 {
		for i, c := range stdComms {
			tok := c
			if i == 0 {
				tok = "{Communities: " + tok
			}
			if i == len(stdComms)-1 {
				tok += "}"
			} else {
				tok += ","
			}
			tokens = append(tokens, tok)
		}
	}
	if len(extComms) > 0 {
		for i, ec := range extComms {
			tok := "[" + ec + "]"
			if i == 0 {
				tok = "{Extcomms: " + tok
			}
			if i == len(extComms)-1 {
				tok += "}"
			} else {
				tok += ","
			}
			tokens = append(tokens, tok)
		}
	}
	if len(largeComms) > 0 {
		for i, lc := range largeComms {
			tok := lc
			if i == 0 {
				tok = "{LargeCommunity: [" + tok
			}
			if i == len(largeComms)-1 {
				tok += "]}"
			} else {
				tok += ","
			}
			tokens = append(tokens, tok)
		}
	}

	if len(tokens) == 0 {
		return strings.TrimRight(leftCols, " ")
	}

	const maxTotalWidth = 215
	indentLen := len(leftCols)
	if indentLen > 92 {
		indentLen = 88
	}
	indent := strings.Repeat(" ", indentLen+1)

	var sb strings.Builder
	sb.WriteString(leftCols)
	sb.WriteString("[")
	curLen := len(leftCols) + 1

	for i, tok := range tokens {
		sep := " "
		if i == 0 {
			sep = ""
		}
		suffix := ""
		if i == len(tokens)-1 {
			suffix = "]"
		}
		piece := sep + tok + suffix
		if i > 0 && curLen+len(piece) > maxTotalWidth {
			sb.WriteString("\n")
			sb.WriteString(indent)
			curLen = len(indent)
			piece = tok + suffix
		}
		sb.WriteString(piece)
		curLen += len(piece)
	}
	return sb.String()
}

func decodeGoBGPPathLine(
	isFirst bool,
	cleanPrefix string,
	vrfRD string,
	familyStr string,
	p *apipb.Path,
) (rawLine string, asns []uint32, rawComms []string, extComms []string) {
	best := (p.GetBest() || isFirst) && !p.GetIsNexthopInvalid()
	nativeAttrs, _ := apiutil.GetNativePathAttributes(p)

	originShort := "i"
	nextHop := ""
	if nh := getNativeNextHop(nativeAttrs); nh != nil {
		nextHop = nh.String()
	}
	localPref := uint32(100)
	med := uint32(0)
	var asPathStr string
	var stdComms []string
	var largeComms []string

	for _, attr := range nativeAttrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeOrigin:
			switch a.Value {
			case bgp.BGP_ORIGIN_ATTR_TYPE_IGP:
				originShort = "i"
			case bgp.BGP_ORIGIN_ATTR_TYPE_EGP:
				originShort = "e"
			default:
				originShort = "?"
			}
		case *bgp.PathAttributeLocalPref:
			localPref = a.Value
		case *bgp.PathAttributeMultiExitDisc:
			med = a.Value
		case *bgp.PathAttributeAsPath:
			asPathStr = bgp.AsPathString(a)
			for _, param := range a.Value {
				switch seg := param.(type) {
				case *bgp.As4PathParam:
					asns = append(asns, seg.AS...)
				case *bgp.AsPathParam:
					for _, n := range seg.AS {
						asns = append(asns, uint32(n))
					}
				}
			}
		case *bgp.PathAttributeCommunities:
			for _, c := range a.Value {
				if c == 0xffff0004 {
					continue
				}
				val := fmt.Sprintf("%d:%d", (c>>16)&0xffff, c&0xffff)
				stdComms = append(stdComms, val)
				rawComms = append(rawComms, val)
			}
		case *bgp.PathAttributeLargeCommunities:
			for _, lc := range a.Values {
				val := lc.String()
				largeComms = append(largeComms, val)
				rawComms = append(rawComms, val)
			}
		case *bgp.PathAttributeExtendedCommunities:
			for _, ec := range a.Value {
				ecStr := strings.TrimSpace(ec.String())
				if vrfRD != "" && strings.EqualFold(ecStr, vrfRD) {
					continue
				}
				extComms = append(extComms, ecStr)
			}
		}
	}

	if asPathStr == "" && len(asns) > 0 {
		parts := make([]string, len(asns))
		for i, n := range asns {
			parts[i] = fmt.Sprintf("%d", n)
		}
		asPathStr = strings.Join(parts, " ")
	}

	rpkiTag := ""
	if p.GetValidation() != nil {
		switch p.GetValidation().GetState() {
		case apipb.Validation_STATE_VALID:
			rpkiTag = "Valid"
		case apipb.Validation_STATE_INVALID:
			rpkiTag = "Invalid"
		}
	}

	ageStr := "00:00:00"
	if ts := p.GetAge(); ts != nil {
		ageStr = formatGoBGPTimedelta(ts.AsTime())
	}

	symbol := "* "
	if best {
		symbol = "*>"
	}
	asDisplay := strings.TrimSpace(asPathStr + " " + originShort)
	var leftCols string
	if familyStr == "ipv6" {
		leftCols = fmt.Sprintf("%-2s %-32s %-30s %-6d %-6d %-9s %-24s ",
			symbol, cleanPrefix, nextHop, localPref, med, ageStr, asDisplay)
	} else {
		leftCols = fmt.Sprintf("%-2s %-20s %-16s %-6d %-6d %-9s %-24s ",
			symbol, cleanPrefix, nextHop, localPref, med, ageStr, asDisplay)
	}
	rawLine = formatFullWidthPathLine(leftCols, stdComms, extComms, largeComms, rpkiTag)
	return rawLine, asns, rawComms, extComms
}

// queryLiveGoBGPNeighbors queries GoBGP's ListPeer gRPC API to return real-time neighbor state, uptime, prefix counts,
// and actual negotiated Add-Path RX / iBGP Next-Hop Unchanged status per VRF.
func (e *Engine) queryLiveGoBGPNeighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	client, err := defaultPool.getClient(rrNode.Endpoint)
	if err != nil {
		return nil, false
	}

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	stream, err := client.ListPeer(cctx, &apipb.ListPeerRequest{EnableAdvertised: false})
	if err != nil {
		return nil, false
	}

	var peers []*apipb.Peer
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		if p := r.GetPeer(); p != nil {
			peers = append(peers, p)
		}
	}

	summaries := make([]models.BGPNeighborSummary, 0, len(views))
	for _, v := range views {
		vrfName := resolveVRFName(v)
		wantGlobal := isGlobalRIB(vrfName)
		hintIP := strings.TrimSpace(v.JuniperSourceIPv4)

		var matchedPeers []*apipb.Peer
		for _, p := range peers {
			confVrf := strings.TrimSpace(p.GetConf().GetVrf())
			peerAddr := strings.TrimSpace(p.GetState().GetNeighborAddress())
			if peerAddr == "" {
				peerAddr = strings.TrimSpace(p.GetConf().GetNeighborAddress())
			}

			if wantGlobal {
				if confVrf != "" {
					continue
				}
				if hintIP != "" && peerAddr != hintIP {
					continue
				}
				matchedPeers = append(matchedPeers, p)
			} else {
				if confVrf != "" {
					if strings.EqualFold(confVrf, vrfName) {
						matchedPeers = append(matchedPeers, p)
					}
					continue
				}
				if hintIP != "" && peerAddr == hintIP {
					matchedPeers = append(matchedPeers, p)
				}
			}
		}

		if len(matchedPeers) == 0 {
			summaries = append(summaries, models.BGPNeighborSummary{
				POP:              rrNode.Location,
				RRNodeID:         rrNode.ID,
				RRNodeName:       rrNode.Name,
				EngineType:       "gobgp",
				ViewID:           v.ID,
				ViewName:         v.Name,
				VRFName:          v.VRFName,
				JunosContext:     fmt.Sprintf("%s %s", v.JunosContextType, v.VRFName),
				NeighborIP:       hintIP,
				PeerASN:          0,
				SessionState:     "No Peer / Idle",
				Uptime:           "-",
				AddPathRx:        false,
				NextHopUnchanged: false,
				PrefixesIPv4:     0,
				PrefixesIPv6:     0,
				UpdatesReceived:  0,
			})
			continue
		}

		for _, matchedPeer := range matchedPeers {
			peerAddr := strings.TrimSpace(matchedPeer.GetState().GetNeighborAddress())
			if peerAddr == "" {
				peerAddr = strings.TrimSpace(matchedPeer.GetConf().GetNeighborAddress())
			}
			peerASN := matchedPeer.GetState().GetPeerAsn()
			if peerASN == 0 {
				peerASN = matchedPeer.GetConf().GetPeerAsn()
			}
			localASN := matchedPeer.GetState().GetLocalAsn()
			if localASN == 0 {
				localASN = matchedPeer.GetConf().GetLocalAsn()
			}

			stateStr := "Idle"
			switch matchedPeer.GetState().GetSessionState() {
			case apipb.PeerState_ESTABLISHED:
				stateStr = "Established"
			case apipb.PeerState_ACTIVE:
				stateStr = "Active"
			case apipb.PeerState_CONNECT:
				stateStr = "Connect"
			case apipb.PeerState_OPENSENT:
				stateStr = "OpenSent"
			case apipb.PeerState_OPENCONFIRM:
				stateStr = "OpenConfirm"
			}

			uptimeStr := "-"
			if stateStr == "Established" && matchedPeer.GetTimers().GetState().GetUptime() != nil {
				uptimeStr = formatGoBGPTimedelta(matchedPeer.GetTimers().GetState().GetUptime().AsTime())
			}

			var rxV4, rxV6, totalRxPfx uint64
			addPathRx := false
			for _, afisafi := range matchedPeer.GetAfiSafis() {
				if ap := afisafi.GetAddPaths(); ap != nil {
					if ap.GetState().GetReceive() || ap.GetConfig().GetReceive() {
						addPathRx = true
					}
				}
				st := afisafi.GetState()
				if st == nil {
					continue
				}
				acc := st.GetAccepted()
				if acc == 0 {
					acc = st.GetReceived()
				}
				totalRxPfx += st.GetReceived()
				if st.GetFamily().GetAfi() == apipb.Family_AFI_IP6 {
					rxV6 += acc
				} else {
					rxV4 += acc
				}
			}

			updatesRx := matchedPeer.GetState().GetMessages().GetReceived().GetUpdate()
			if updatesRx == 0 {
				updatesRx = totalRxPfx
			}

			// Next-Hop is preserved unmodified on GoBGP read-only iBGP collectors and Route Server clients
			nhUnchanged := matchedPeer.GetState().GetType() == apipb.PeerType_INTERNAL ||
				matchedPeer.GetConf().GetType() == apipb.PeerType_INTERNAL ||
				(localASN > 0 && localASN == peerASN) ||
				matchedPeer.GetRouteServer().GetRouteServerClient()

			summaries = append(summaries, models.BGPNeighborSummary{
				POP:              rrNode.Location,
				RRNodeID:         rrNode.ID,
				RRNodeName:       rrNode.Name,
				EngineType:       "gobgp",
				ViewID:           v.ID,
				ViewName:         v.Name,
				VRFName:          v.VRFName,
				JunosContext:     fmt.Sprintf("%s %s", v.JunosContextType, v.VRFName),
				NeighborIP:       peerAddr,
				PeerASN:          peerASN,
				SessionState:     stateStr,
				Uptime:           uptimeStr,
				AddPathRx:        addPathRx,
				NextHopUnchanged: nhUnchanged,
				PrefixesIPv4:     int(rxV4),
				PrefixesIPv6:     int(rxV6),
				UpdatesReceived:  int64(updatesRx),
			})
		}
	}

	return summaries, true
}
