// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

type grpcConnPool struct {
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

var defaultPool = &grpcConnPool{
	conns: make(map[string]*grpc.ClientConn),
}

func (p *grpcConnPool) setConn(endpoint string, conn *grpc.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns[endpoint] = conn
}

func (p *grpcConnPool) closeEndpoint(endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn, ok := p.conns[endpoint]; ok {
		_ = conn.Close()
		delete(p.conns, endpoint)
	}
}

func (p *grpcConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, conn := range p.conns {
		_ = conn.Close()
		delete(p.conns, k)
	}
}

// CloseGRPCConnection closes and removes a cached gRPC connection when an RR node is updated or deleted.
func CloseGRPCConnection(endpoint string) {
	defaultPool.closeEndpoint(strings.TrimSpace(endpoint))
}

// CloseAllGRPCConnections closes all pooled gRPC client connections during graceful shutdown.
func CloseAllGRPCConnections() {
	defaultPool.closeAll()
}

func (p *grpcConnPool) getClient(endpoint string) (apipb.GobgpApiClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.conns[endpoint]; ok {
		return apipb.NewGobgpApiClient(conn), nil
	}

	targetURI := endpoint
	if !strings.Contains(targetURI, "://") {
		targetURI = "passthrough:///" + targetURI
	}
	conn, err := grpc.NewClient(
		targetURI,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64*1024*1024)),
	)
	if err != nil {
		return nil, err
	}
	p.conns[endpoint] = conn
	return apipb.NewGobgpApiClient(conn), nil
}

// resolveGoBGPVrfRD queries GoBGP's ListVrf gRPC API to resolve a VRF name (e.g. "VRF-CN-OPTIMIZE")
// to its Route Distinguisher string (e.g. "18013:1").
// Also returns true if the GoBGP gRPC server responded (proving the gRPC connection is live).
func (e *Engine) resolveGoBGPVrfRD(ctx context.Context, client apipb.GobgpApiClient, vrfName string) (string, bool) {
	stream, err := client.ListVrf(ctx, &apipb.ListVrfRequest{})
	if err != nil {
		return "", false
	}

	var firstVrfRD string
	vrfCount := 0
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		v := r.GetVrf()
		if v == nil {
			continue
		}
		rdObj, errRD := apiutil.UnmarshalRD(v.GetRd())
		if errRD != nil || rdObj == nil {
			continue
		}
		rdStr := rdObj.String()
		vrfCount++
		if firstVrfRD == "" {
			firstVrfRD = rdStr
		}
		if strings.EqualFold(strings.TrimSpace(v.GetName()), strings.TrimSpace(vrfName)) || strings.EqualFold(rdStr, strings.TrimSpace(vrfName)) {
			return rdStr, true
		}
	}

	// If the user entered an RD directly (e.g. "18013:1"), validate and return it
	if !isGlobalRIB(vrfName) {
		if _, err := bgp.ParseRouteDistinguisher(vrfName); err == nil {
			return vrfName, true
		}
	}

	// If VRF name was set to "global" but the RR only has 1 VRF configured, return empty RD here
	// (caller can fall back to firstVrfRD if global unicast table is empty).
	return "", true
}

// queryLiveGoBGPgRPC queries GoBGP directly over native gRPC (ListVrf + ListPath RPC) without any CLI command execution.
// When a VRF is configured (e.g. VRF-CN-OPTIMIZE with RD 18013:1), GoBGP stores VRF routes in the global
// VPNv4/VPNv6 table (`SAFI_MPLS_VPN`) indexed by RD. Querying `TableType_GLOBAL` with `SAFI_MPLS_VPN`, `Rd`,
// and `TableLookupPrefix_SHORTER` performs an O(1) radix/hash lookup (identical to `gobgp global rib <ip>/32 rd <rd> shorter-prefixes -a vpnv4`).
func (e *Engine) queryLiveGoBGPgRPC(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	client, err := defaultPool.getClient(rrNode.Endpoint)
	if err != nil {
		return nil, "", "", false
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
			return nil, "", "", false
		}
		familyStr = fam
		isExactPrefix = isPrefix
		if isPrefix {
			lookupCIDR = normalized
		} else {
			if fam == "ipv6" {
				lookupCIDR = normalized + "/128"
			} else {
				lookupCIDR = normalized + "/32"
			}
		}
	} else if strings.Contains(target, ":") && strings.Count(target, ":") > 2 {
		familyStr = "ipv6"
	}

	afi := apipb.Family_AFI_IP
	neighborIP := view.JuniperSourceIPv4
	if familyStr == "ipv6" {
		afi = apipb.Family_AFI_IP6
		if view.JuniperSourceIPv6 != "" {
			neighborIP = view.JuniperSourceIPv6
		}
	}

	vrfName := resolveVRFName(view)
	rdStr, grpcAlive := e.resolveGoBGPVrfRD(cctx, client, vrfName)
	if !grpcAlive {
		return nil, "", "", false
	}

	// Helper to run a ListPath query with given family, RD, and lookup type
	runLookup := func(tableType apipb.TableType, tableName string, safi apipb.Family_Safi, rd string, lType apipb.TableLookupPrefix_Type) ([]models.BGPRoutePath, string, string, bool) {
		var prefixes []*apipb.TableLookupPrefix
		batchSize := uint64(0)
		sortType := apipb.ListPathRequest_PREFIX
		onlyBinary := false

		if queryType == "prefix" && lookupCIDR != "" {
			prefixes = []*apipb.TableLookupPrefix{
				{
					Prefix: lookupCIDR,
					Rd:     rd,
					Type:   lType,
				},
			}
		} else {
			// For AS-Path or Community scans, stream in small batches with EnableOnlyBinary=true
			// so GoBGP skips expensive protobuf Any reflection on all 1.62M routes.
			batchSize = 64
			sortType = apipb.ListPathRequest_NONE
			onlyBinary = true
		}
		req := &apipb.ListPathRequest{
			TableType: tableType,
			Name:      tableName,
			Family: &apipb.Family{
				Afi:  afi,
				Safi: safi,
			},
			Prefixes:         prefixes,
			SortType:         sortType,
			BatchSize:        batchSize,
			EnableOnlyBinary: onlyBinary,
		}
		return e.fetchPathsFromStream(cctx, client, req, rrNode, view, familyStr, queryType, target, rd)
	}

	// Case 1: VRF Mode (VRF has an RD in GoBGP, e.g. VRF-CN-OPTIMIZE -> RD 18013:1)
	// Equivalent to: `gobgp global rib <ip>/32 rd <rd> shorter-prefixes -a vpnv4` (or vpnv6)
	if rdStr != "" {
		if queryType == "prefix" && isExactPrefix {
			if paths, matched, rawOut, ok := runLookup(apipb.TableType_GLOBAL, "", apipb.Family_SAFI_MPLS_VPN, rdStr, apipb.TableLookupPrefix_EXACT); ok && len(paths) > 0 {
				return paths, matched, rawOut, true
			}
		}
		if paths, matched, rawOut, ok := runLookup(apipb.TableType_GLOBAL, "", apipb.Family_SAFI_MPLS_VPN, rdStr, apipb.TableLookupPrefix_SHORTER); ok {
			if len(paths) > 0 {
				return paths, matched, rawOut, true
			}
			if queryType != "prefix" {
				emptyRaw := fmt.Sprintf("# Node: %s (%s @ %s) | Engine: GOBGP (gRPC)\n# VRF: %s (RD: %s) | Target: %s\nNetwork not in table.\n",
					rrNode.Name, rrNode.LoopbackIP, rrNode.Endpoint, vrfName, rdStr, target)
				return []models.BGPRoutePath{}, "No matching route", emptyRaw, true
			}
		}
	}

	// Case 2: Single Global Unicast RIB (`vrf_name` is empty / "global" or VRF has no VPN RD)
	// Equivalent to: `gobgp global rib <ip>/32 shorter-prefixes -a ipv4` (or ipv6)
	if isGlobalRIB(vrfName) || rdStr == "" {
		if queryType == "prefix" && isExactPrefix {
			if paths, matched, rawOut, ok := runLookup(apipb.TableType_GLOBAL, "", apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_EXACT); ok && len(paths) > 0 {
				return paths, matched, rawOut, true
			}
		}
		if paths, matched, rawOut, ok := runLookup(apipb.TableType_GLOBAL, "", apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_SHORTER); ok {
			if len(paths) > 0 {
				return paths, matched, rawOut, true
			}
			if queryType != "prefix" {
				emptyRaw := fmt.Sprintf("# Node: %s (%s @ %s) | Engine: GOBGP (gRPC)\n# VRF: %s (RD: %s) | Target: %s\nNetwork not in table.\n",
					rrNode.Name, rrNode.LoopbackIP, rrNode.Endpoint, vrfName, rdStr, target)
				return []models.BGPRoutePath{}, "No matching route", emptyRaw, true
			}
		}
	}

	// Case 3: Neighbor Adj-RIB-In fallback (`gobgp neighbor <ip> adj-in <ip>/32 shorter-prefixes`)
	if neighborIP != "" {
		if paths, matched, rawOut, ok := runLookup(apipb.TableType_ADJ_IN, neighborIP, apipb.Family_SAFI_UNICAST, "", apipb.TableLookupPrefix_SHORTER); ok && len(paths) > 0 {
			return paths, matched, rawOut, true
		}
	}

	// The gRPC server is reachable and alive, but no route matched in the RIB.
	// Return an empty live result (`ok = true` with 0 paths) so we NEVER fall back to fake mock routes!
	emptyRaw := fmt.Sprintf("# Node: %s (%s @ %s) | Engine: GOBGP (gRPC)\n# VRF: %s (RD: %s) | Target: %s\nNetwork not in table.\n",
		rrNode.Name, rrNode.LoopbackIP, rrNode.Endpoint, vrfName, rdStr, target)
	return []models.BGPRoutePath{}, "No matching route", emptyRaw, true
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
		if l, err := strconv.Atoi(clean[idx+1:]); err == nil {
			return l
		}
	}
	return -1
}

func matchesASPathQuery(routePath models.BGPRoutePath, rawQuery string) bool {
	cleaned := strings.NewReplacer("^", " ", "$", " ", "_", " ", ",", " ").Replace(rawQuery)
	tokens := strings.Fields(cleaned)
	var normTokens []string
	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		if strings.HasPrefix(upper, "AS") && len(tok) > 2 {
			tok = tok[2:]
		}
		tok = strings.Trim(tok, ".*+?[]()-")
		if tok != "" {
			normTokens = append(normTokens, tok)
		}
	}
	if len(normTokens) == 0 {
		return false
	}
	if len(normTokens) == 1 {
		want := normTokens[0]
		for _, hop := range routePath.ASPath {
			if strconv.FormatUint(uint64(hop.ASN), 10) == want {
				return true
			}
		}
		return strings.Contains(" "+routePath.ASPathString+" ", " "+want+" ")
	}
	seq := strings.Join(normTokens, " ")
	return strings.Contains(" "+routePath.ASPathString+" ", " "+seq+" ")
}

func matchesCommunityQuery(routePath models.BGPRoutePath, rawLine string, rawQuery string) bool {
	want := strings.TrimSpace(rawQuery)
	if want == "" {
		return false
	}
	for _, c := range routePath.Communities {
		if strings.EqualFold(c.Raw, want) {
			return true
		}
	}
	for _, ec := range routePath.ExtCommunities {
		if strings.EqualFold(ec, want) || strings.Contains(strings.ToLower(ec), strings.ToLower(want)) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(rawLine), strings.ToLower(want))
}

func fastMatchBinaryPath(pattrsBin [][]byte, queryType string, rawQuery string) bool {
	if len(pattrsBin) == 0 {
		return true // fall back to full decode when binary attributes are not populated
	}
	if queryType == "aspath" {
		cleaned := strings.NewReplacer("^", " ", "$", " ", "_", " ", ",", " ").Replace(rawQuery)
		tokens := strings.Fields(cleaned)
		var normTokens []string
		for _, tok := range tokens {
			upper := strings.ToUpper(tok)
			if strings.HasPrefix(upper, "AS") && len(tok) > 2 {
				tok = tok[2:]
			}
			tok = strings.Trim(tok, ".*+?[]()-")
			if tok != "" {
				normTokens = append(normTokens, tok)
			}
		}
		if len(normTokens) == 0 {
			return false
		}
		var singleASN uint32
		isSingle := false
		if len(normTokens) == 1 {
			if n, err := strconv.ParseUint(normTokens[0], 10, 32); err == nil {
				singleASN = uint32(n)
				isSingle = true
			}
		}
		seq := strings.Join(normTokens, " ")

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
			if isSingle {
				for _, param := range asAttr.Value {
					switch seg := param.(type) {
					case *bgp.As4PathParam:
						for _, asn := range seg.AS {
							if asn == singleASN {
								return true
							}
						}
					case *bgp.AsPathParam:
						for _, asn := range seg.AS {
							if uint32(asn) == singleASN {
								return true
							}
						}
					}
				}
			} else {
				asStr := bgp.AsPathString(asAttr)
				if strings.Contains(" "+asStr+" ", " "+seq+" ") {
					return true
				}
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
			if h, err1 := strconv.ParseUint(parts[0], 10, 16); err1 == nil {
				if l, err2 := strconv.ParseUint(parts[1], 10, 16); err2 == nil {
					stdTarget = (uint32(h) << 16) | uint32(l)
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
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	familyStr string,
	queryType string,
	target string,
	rd string,
) ([]models.BGPRoutePath, string, string, bool) {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream, err := client.ListPath(streamCtx, req)
	if err != nil {
		return nil, "", "", false
	}

	showLabel := req.GetFamily().GetSafi() == apipb.Family_SAFI_MPLS_VPN

	// Mode A: Stream-filter on-the-fly for AS-Path or Community queries (stops immediately once 50 matching paths are found)
	if queryType == "aspath" || queryType == "community" {
		const maxFilterMatches = 50
		var results []models.BGPRoutePath
		var rawLines []string
		pathSeq := uint32(1)
		receivedAny := false

		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				// If context deadline expired after streaming started, return any matches collected so far
				if receivedAny || len(results) > 0 {
					break
				}
				return nil, "", "", false
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
				routePath, rawLine := e.decodeGoBGPPath(pathSeq, idx == 0, cleanPfx, rd, familyStr, view, p, showLabel)
				if queryType == "aspath" {
					if !matchesASPathQuery(routePath, target) {
						continue
					}
				} else if queryType == "community" {
					if !matchesCommunityQuery(routePath, rawLine, target) {
						continue
					}
				}
				pathSeq++
				results = append(results, routePath)
				rawLines = append(rawLines, rawLine)
				if len(results) >= maxFilterMatches {
					cancelStream()
					break
				}
			}
			if len(results) >= maxFilterMatches {
				break
			}
		}

		if len(results) == 0 {
			return nil, "", "", true
		}

		var rawBuilder strings.Builder
		rawBuilder.WriteString(fmt.Sprintf("   %-20s %-16s %-6s %-6s %-9s %-24s %s\n",
			"Network", "Next Hop", "LocPrf", "MED", "Age", "AS_PATH", "Attrs"))
		for _, line := range rawLines {
			rawBuilder.WriteString(line + "\n")
		}

		summaryLabel := fmt.Sprintf("Filter: %s (%d routes)", target, len(results))
		return results, summaryLabel, rawBuilder.String(), true
	}

	// Mode B: Prefix lookup (O(1) radix/hash lookup with Longest Prefix Match selection)
	var allDests []*apipb.Destination
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", "", false
		}
		if dest := resp.GetDestination(); dest != nil && len(dest.GetPaths()) > 0 {
			allDests = append(allDests, dest)
		}
	}

	if len(allDests) == 0 {
		return nil, "", "", true
	}

	selectedDests := allDests
	if len(allDests) > 1 {
		bestDest := allDests[0]
		bestMask := maskLengthOfPrefix(bestDest.GetPrefix(), rd)
		for _, d := range allDests[1:] {
			m := maskLengthOfPrefix(d.GetPrefix(), rd)
			if m >= bestMask {
				bestMask = m
				bestDest = d
			}
		}
		selectedDests = []*apipb.Destination{bestDest}
	}

	var results []models.BGPRoutePath
	var rawLines []string
	var matchedPrefix string
	pathSeq := uint32(1)

	for _, dest := range selectedDests {
		cleanPfx := stripRDFromPrefix(dest.GetPrefix(), rd)
		if matchedPrefix == "" {
			matchedPrefix = cleanPfx
		}
		for idx, p := range dest.GetPaths() {
			routePath, rawLine := e.decodeGoBGPPath(pathSeq, idx == 0, cleanPfx, rd, familyStr, view, p, showLabel)
			pathSeq++
			results = append(results, routePath)
			rawLines = append(rawLines, rawLine)
		}
	}

	var rawBuilder strings.Builder
	rawBuilder.WriteString(fmt.Sprintf("   %-20s %-16s %-6s %-6s %-9s %-24s %s\n",
		"Network", "Next Hop", "LocPrf", "MED", "Age", "AS_PATH", "Attrs"))
	for _, line := range rawLines {
		rawBuilder.WriteString(line + "\n")
	}

	return results, matchedPrefix, rawBuilder.String(), true
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

func formatFullWidthPathLine(leftCols string, stdComms, extComms, largeComms []string) string {
	var tokens []string
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

func (e *Engine) decodeGoBGPPath(
	seqID uint32,
	isFirst bool,
	cleanPrefix string,
	vrfRD string,
	familyStr string,
	view models.RouteViewMeta,
	p *apipb.Path,
	showLabel bool,
) (models.BGPRoutePath, string) {
	best := (p.GetBest() || isFirst) && !p.GetIsNexthopInvalid()
	pathID := p.GetIdentifier()
	if pathID == 0 {
		pathID = seqID
	}

	peerIP := p.GetNeighborIp()
	if peerIP == "" || peerIP == "<nil>" {
		peerIP = view.JuniperSourceIPv4
	}

	nativeAttrs, _ := apiutil.GetNativePathAttributes(p)

	originStr := "IGP"
	originShort := "i"
	nextHop := ""
	if nh := getNativeNextHop(nativeAttrs); nh != nil {
		nextHop = nh.String()
	}
	localPref := uint32(100)
	med := uint32(0)
	var asns []uint32
	var asPathStr string
	var stdComms []string
	var largeComms []string
	var rawComms []string
	var extComms []string
	var originatorID string
	var clusterList []string

	for _, attr := range nativeAttrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeOrigin:
			switch a.Value {
			case bgp.BGP_ORIGIN_ATTR_TYPE_IGP:
				originStr = "IGP"
				originShort = "i"
			case bgp.BGP_ORIGIN_ATTR_TYPE_EGP:
				originStr = "EGP"
				originShort = "e"
			default:
				originStr = "Incomplete"
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
					continue // Skip internal RFC/Juniper route-filter-translated-v6 marker
				}
				high := (c >> 16) & 0xffff
				low := c & 0xffff
				val := fmt.Sprintf("%d:%d", high, low)
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
				// Filter out the GoBGP VRF's internal Route-Target (matching vrfRD) while keeping all Traffic Engineering Extcomms
				if vrfRD != "" && strings.EqualFold(ecStr, vrfRD) {
					continue
				}
				extComms = append(extComms, ecStr)
			}
		case *bgp.PathAttributeOriginatorId:
			if a.Value != nil {
				originatorID = a.Value.String()
			}
		case *bgp.PathAttributeClusterList:
			for _, cl := range a.Value {
				clusterList = append(clusterList, cl.String())
			}
		}
	}

	hops := make([]models.ASHop, 0, len(asns))
	strParts := make([]string, 0, len(asns))
	for _, asn := range asns {
		hops = append(hops, e.ResolveASN(asn))
		strParts = append(strParts, strconv.FormatUint(uint64(asn), 10))
	}
	if asPathStr == "" {
		asPathStr = strings.Join(strParts, " ")
	}

	var originASN uint32
	var originName string
	if len(hops) > 0 {
		last := hops[len(hops)-1]
		originASN = last.ASN
		originName = last.Name
	}

	rpkiStr := "NotFound"
	if p.GetValidation() != nil {
		switch p.GetValidation().GetState() {
		case apipb.Validation_STATE_VALID:
			rpkiStr = "Valid"
		case apipb.Validation_STATE_INVALID:
			rpkiStr = "Invalid"
		}
	}

	ageStr := "00:00:00"
	if ts := p.GetAge(); ts != nil {
		ageStr = formatGoBGPTimedelta(ts.AsTime())
	}

	var metaParts []string
	if len(extComms) > 0 {
		metaParts = append(metaParts, fmt.Sprintf("ExtComms: [%s]", strings.Join(extComms, ", ")))
	}
	if originatorID != "" {
		metaParts = append(metaParts, fmt.Sprintf("Originator: %s", originatorID))
	}
	if len(clusterList) > 0 {
		metaParts = append(metaParts, fmt.Sprintf("ClusterList: [%s]", strings.Join(clusterList, " ")))
	}

	ispLabel := fmt.Sprintf("Original eBGP Next-Hop (%s)", view.Name)
	if len(metaParts) > 0 {
		ispLabel = strings.Join(metaParts, " · ")
	}

	note := fmt.Sprintf("Add-Path Candidate (#%d)", seqID)
	if best {
		note = "Best Path (*> Selected in GoBGP RIB)"
	}

	symbol := "* "
	if best {
		symbol = "*>"
	}
	asDisplay := strings.TrimSpace(asPathStr + " " + originShort)
	leftCols := fmt.Sprintf("%-2s %-20s %-16s %-6d %-6d %-9s %-24s ",
		symbol, cleanPrefix, nextHop, localPref, med, ageStr, asDisplay)
	rawLine := formatFullWidthPathLine(leftCols, stdComms, extComms, largeComms)

	return models.BGPRoutePath{
		PathID:         pathID,
		Prefix:         cleanPrefix,
		AddressFamily:  familyStr,
		Best:           best,
		NextHop:        nextHop,
		NextHopISP:     ispLabel,
		ASPath:         hops,
		ASPathString:   asPathStr,
		Origin:         originStr,
		LocalPref:      localPref,
		MED:            med,
		Communities:    e.TranslateCommunities(rawComms),
		ExtCommunities: extComms,
		PeerIP:         peerIP,
		OriginASN:      originASN,
		OriginName:     originName,
		RPKIStatus:     rpkiStr,
		Age:            ageStr,
		ValidationNote: note,
	}, rawLine
}

// queryLiveGoBGPNeighbors queries GoBGP's ListPeer gRPC API to return real-time neighbor state, uptime, and prefix counts
// strictly matched per VRF on this specific RR node. Never borrows another VRF's peer!
// Returns (summaries, rrReachable).
func (e *Engine) queryLiveGoBGPNeighbors(ctx context.Context, rrNode models.RRNodeConfig, views []models.RouteViewMeta) ([]models.BGPNeighborSummary, bool) {
	client, err := defaultPool.getClient(rrNode.Endpoint)
	if err != nil {
		return nil, false
	}

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	stream, err := client.ListPeer(cctx, &apipb.ListPeerRequest{})
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
				NextHopUnchanged: true,
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

			var rxV4, rxV6, totalRx uint64
			for _, afisafi := range matchedPeer.GetAfiSafis() {
				st := afisafi.GetState()
				if st == nil {
					continue
				}
				acc := st.GetAccepted()
				if acc == 0 {
					acc = st.GetReceived()
				}
				totalRx += st.GetReceived()
				if st.GetFamily().GetAfi() == apipb.Family_AFI_IP6 {
					rxV6 += acc
				} else {
					rxV4 += acc
				}
			}

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
				AddPathRx:        true,
				NextHopUnchanged: true,
				PrefixesIPv4:     int(rxV4),
				PrefixesIPv6:     int(rxV6),
				UpdatesReceived:  int64(totalRx),
			})
		}
	}

	return summaries, true
}
