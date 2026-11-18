package bgp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

var wellKnownASNs = map[uint32]struct {
	Name string
	Tier string
}{
	2914:   {"NTT Global IP Network", "tier1"},
	3491:   {"PCCW Global", "tier1"},
	4637:   {"Telstra Global", "tier1"},
	3356:   {"Lumen (Level3)", "tier1"},
	174:    {"Cogent Communications", "tier1"},
	1299:   {"Arelion (Telia Carrier)", "tier1"},
	6939:   {"Hurricane Electric (HE)", "tier1"},
	6453:   {"TATA Communications", "tier1"},
	4809:   {"China Telecom Next Carrying Network (CN2)", "cn_carrier"},
	4134:   {"Chinanet Backbone", "cn_carrier"},
	4812:   {"China Telecom Regional Network", "cn_carrier"},
	23764:  {"China Telecom Global (CTGNet)", "cn_carrier"},
	58453:  {"China Mobile International (CMI)", "cn_carrier"},
	9808:   {"China Mobile Backbone", "cn_carrier"},
	22427:  {"China Mobile International Peer", "cn_carrier"},
	10099:  {"China Unicom Global (CUG)", "cn_carrier"},
	4837:   {"China Unicom 169 Backbone", "cn_carrier"},
	15169:  {"Google LLC", "customer"},
	13335:  {"Cloudflare, Inc.", "customer"},
	8075:   {"Microsoft Corporation", "customer"},
	16509:  {"Amazon.com (AWS)", "customer"},
	32934:  {"Meta Platforms", "customer"},
	20940:  {"Akamai International", "customer"},
	45102:  {"Alibaba Cloud", "customer"},
	132203: {"Tencent Cloud", "customer"},
}

type Engine struct {
	store *store.AppStore
	cache *security.TTLCache
}

func NewEngine(st *store.AppStore, cache *security.TTLCache) *Engine {
	return &Engine{
		store: st,
		cache: cache,
	}
}

func (e *Engine) ResolveASN(asn uint32) models.ASHop {
	if info, ok := wellKnownASNs[asn]; ok {
		return models.ASHop{
			ASN:  asn,
			Name: info.Name,
			Tier: info.Tier,
		}
	}
	return models.ASHop{
		ASN:  asn,
		Name: fmt.Sprintf("AS%d", asn),
		Tier: "customer",
	}
}

func (e *Engine) TranslateCommunities(rawList []string) []models.CommunityItem {
	dict := e.store.GetCommunities()
	dictMap := make(map[string]models.CommunityDictEntry, len(dict))
	for _, d := range dict {
		dictMap[d.Community] = d
	}

	out := make([]models.CommunityItem, 0, len(rawList))
	for _, raw := range rawList {
		if entry, ok := dictMap[raw]; ok {
			out = append(out, models.CommunityItem{
				Raw:      raw,
				Label:    entry.Label,
				Category: entry.Category,
			})
		} else {
			out = append(out, models.CommunityItem{
				Raw:      raw,
				Label:    "BGP Community",
				Category: "upstream",
			})
		}
	}
	return out
}

// selectCandidateRRNodes returns an ordered slice of enabled RR nodes to query (supporting Multi-POP + Multi-RR with automatic Primary -> Backup failover).
// It enforces that at least 1 enabled RR node must be configured in the Web Admin Console before queries can run.
func (e *Engine) selectCandidateRRNodes(requestedID string, requestedPOP string, targetEngine string) ([]models.RRNodeConfig, error) {
	nodes := e.store.GetRRNodes()
	var enabledNodes []models.RRNodeConfig
	for _, n := range nodes {
		if n.Enabled && strings.TrimSpace(n.Endpoint) != "" {
			enabledNodes = append(enabledNodes, n)
		}
	}
	if len(enabledNodes) == 0 {
		return nil, fmt.Errorf("no active Route Reflector (RR) node is configured or enabled; please configure at least 1 RR node in the Web Admin Console (Section 3: RR Collector Nodes)")
	}

	reqID := strings.TrimSpace(requestedID)
	if reqID != "" && !strings.EqualFold(reqID, "auto") {
		for _, n := range enabledNodes {
			if n.ID == reqID {
				return []models.RRNodeConfig{n}, nil
			}
		}
		return nil, fmt.Errorf("selected Route Reflector (RR) node %q is not found or is currently disabled", reqID)
	}

	// Filter by requested POP location if specified (Multi-POP support)
	popFilter := strings.TrimSpace(requestedPOP)
	pool := enabledNodes
	if popFilter != "" && !strings.EqualFold(popFilter, "all") && !strings.EqualFold(popFilter, "auto") {
		var popNodes []models.RRNodeConfig
		for _, n := range enabledNodes {
			if strings.EqualFold(strings.TrimSpace(n.Location), popFilter) {
				popNodes = append(popNodes, n)
			}
		}
		if len(popNodes) > 0 {
			pool = popNodes
		}
	}

	eng := strings.ToLower(strings.TrimSpace(targetEngine))
	var candidates []models.RRNodeConfig
	added := make(map[string]bool)

	addMatching := func(matchEngine bool, primaryOnly bool) {
		for _, n := range pool {
			if added[n.ID] {
				continue
			}
			nEng := strings.ToLower(strings.TrimSpace(n.EngineType))
			isPrimary := strings.EqualFold(n.Role, "primary")
			if matchEngine && eng != "" && eng != "auto" && nEng != eng {
				continue
			}
			if primaryOnly && !isPrimary {
				continue
			}
			candidates = append(candidates, n)
			added[n.ID] = true
		}
	}

	// 1. Primary RR nodes in target POP matching the VRF's engine type (gobgp / bird2 / frr)
	addMatching(true, true)
	// 2. Backup/Secondary RR nodes in target POP matching the VRF's engine type
	addMatching(true, false)
	// 3. Any remaining Primary RR nodes in target POP
	addMatching(false, true)
	// 4. Any remaining Backup/Secondary RR nodes in target POP
	addMatching(false, false)

	return candidates, nil
}

func (e *Engine) ExecuteLookup(ctx context.Context, req models.LookupRequest) (*models.LookupResponse, error) {
	settings := e.store.GetSettings()
	baseCandidates, err := e.selectCandidateRRNodes(req.RRNodeID, req.POP, req.Engine)
	if err != nil {
		return nil, err
	}
	primaryRR := baseCandidates[0]
	engineType := req.Engine
	if engineType == "" || engineType == "auto" {
		engineType = primaryRR.EngineType
	}

	viewMap := e.store.GetRouteViewMap()
	results := make([]models.ViewQueryResult, len(req.Views))
	var wg sync.WaitGroup

	ttl := time.Duration(settings.CacheTTLSeconds) * time.Second

	for idx, viewID := range req.Views {
		viewMeta, ok := viewMap[viewID]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(i int, vm models.RouteViewMeta) {
			defer wg.Done()
			vrfEngine := strings.ToLower(strings.TrimSpace(vm.Type))
			if req.Engine != "" && req.Engine != "auto" {
				vrfEngine = strings.ToLower(strings.TrimSpace(req.Engine))
			}
			if vrfEngine == "" {
				vrfEngine = engineType
			}

			targetPOP := req.POP
			if (targetPOP == "" || strings.EqualFold(targetPOP, "all")) && vm.POP != "" && !strings.EqualFold(vm.POP, "all") {
				targetPOP = vm.POP
			}

			candidates, errCand := e.selectCandidateRRNodes(req.RRNodeID, targetPOP, vrfEngine)
			if errCand != nil || len(candidates) == 0 {
				candidates = baseCandidates
			}

			cacheKey := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", candidates[0].ID, targetPOP, vrfEngine, req.QueryType, req.Target, vm.ID, vm.VRFName)
			if cachedRes, hit := e.cache.Get(cacheKey); hit {
				results[i] = cachedRes
				return
			}

			start := time.Now()
			res := e.querySingleViewWithFailover(ctx, candidates, vrfEngine, vm, req.QueryType, req.Target)
			res.QueryTimeMs = time.Since(start).Milliseconds()
			if res.QueryTimeMs == 0 {
				res.QueryTimeMs = 1
			}
			// Only cache successful live queries
			if res.MatchedNet != "RR Connection Failed" {
				e.cache.Set(cacheKey, res, ttl)
			}
			results[i] = res
		}(idx, viewMeta)
	}
	wg.Wait()

	usedRRDisplay := fmt.Sprintf("%s (%s @ %s)", primaryRR.Name, primaryRR.LoopbackIP, primaryRR.Endpoint)
	if len(results) > 0 && results[0].RRNodeName != "" {
		for _, n := range baseCandidates {
			if n.ID == results[0].RRNodeID {
				usedRRDisplay = fmt.Sprintf("%s (%s @ %s)", n.Name, n.LoopbackIP, n.Endpoint)
				break
			}
		}
	}

	return &models.LookupResponse{
		QueryType:  req.QueryType,
		Target:     req.Target,
		RRNodeUsed: usedRRDisplay,
		EngineUsed: strings.ToUpper(engineType),
		Timestamp:  time.Now(),
		Results:    results,
	}, nil
}

// querySingleViewWithFailover queries 1 or multiple configured RR nodes in priority order (Primary -> Backup failover).
// It NEVER returns simulated or demo routes; if all configured RRs are unreachable, it returns an explicit connection failure result.
func (e *Engine) querySingleViewWithFailover(
	ctx context.Context,
	candidates []models.RRNodeConfig,
	engineType string,
	view models.RouteViewMeta,
	queryType string,
	target string,
) models.ViewQueryResult {
	for _, rrNode := range candidates {
		activeEngine := engineType
		if activeEngine == "" || activeEngine == "auto" {
			activeEngine = strings.ToLower(strings.TrimSpace(rrNode.EngineType))
		}
		switch activeEngine {
		case "gobgp":
			if livePaths, matchedNet, rawOut, ok := e.queryLiveGoBGPgRPC(ctx, rrNode, view, queryType, target); ok {
				return models.ViewQueryResult{
					View:        view,
					RRNodeID:    rrNode.ID,
					RRNodeName:  rrNode.Name,
					EngineType:  "gobgp",
					QueryTarget: target,
					MatchedNet:  matchedNet,
					TotalPaths:  len(livePaths),
					Paths:       livePaths,
					RawOutput:   rawOut,
				}
			}
		case "bird2":
			if livePaths, matchedNet, rawOut, ok := e.queryLiveBird2VRF(ctx, rrNode, view, queryType, target); ok {
				return models.ViewQueryResult{
					View:        view,
					RRNodeID:    rrNode.ID,
					RRNodeName:  rrNode.Name,
					EngineType:  "bird2",
					QueryTarget: target,
					MatchedNet:  matchedNet,
					TotalPaths:  len(livePaths),
					Paths:       livePaths,
					RawOutput:   rawOut,
				}
			}
		case "frr":
			if livePaths, matchedNet, rawOut, ok := e.queryLiveFrrVRF(ctx, rrNode, view, queryType, target); ok {
				return models.ViewQueryResult{
					View:        view,
					RRNodeID:    rrNode.ID,
					RRNodeName:  rrNode.Name,
					EngineType:  "frr",
					QueryTarget: target,
					MatchedNet:  matchedNet,
					TotalPaths:  len(livePaths),
					Paths:       livePaths,
					RawOutput:   rawOut,
				}
			}
		}
	}

	rrNode := candidates[0]
	errRaw := fmt.Sprintf("# Error: Unable to query Route Reflector %s (%s) via %s.\n# Please verify that the RR daemon (gobgpd gRPC / birdc / vtysh) is running and reachable at %s.\n",
		rrNode.Name, rrNode.LoopbackIP, strings.ToUpper(engineType), rrNode.Endpoint)

	return models.ViewQueryResult{
		View:        view,
		RRNodeID:    rrNode.ID,
		RRNodeName:  rrNode.Name,
		EngineType:  engineType,
		QueryTarget: target,
		MatchedNet:  "RR Connection Failed",
		TotalPaths:  0,
		Paths:       []models.BGPRoutePath{},
		RawOutput:   errRaw,
	}
}

func (e *Engine) buildPath(
	id uint32,
	prefix string,
	family string,
	best bool,
	nextHop string,
	nextHopISP string,
	asns []uint32,
	localPref uint32,
	med uint32,
	comms []string,
	peerIP string,
	rpki string,
	age string,
	note string,
) models.BGPRoutePath {
	hops := make([]models.ASHop, 0, len(asns))
	strParts := make([]string, 0, len(asns))
	for _, asn := range asns {
		hops = append(hops, e.ResolveASN(asn))
		strParts = append(strParts, strconv.FormatUint(uint64(asn), 10))
	}
	var originASN uint32
	var originName string
	if len(hops) > 0 {
		last := hops[len(hops)-1]
		originASN = last.ASN
		originName = last.Name
	}
	return models.BGPRoutePath{
		PathID:         id,
		Prefix:         prefix,
		AddressFamily:  family,
		Best:           best,
		NextHop:        nextHop,
		NextHopISP:     nextHopISP,
		ASPath:         hops,
		ASPathString:   strings.Join(strParts, " "),
		Origin:         "IGP",
		LocalPref:      localPref,
		MED:            med,
		Communities:    e.TranslateCommunities(comms),
		ExtCommunities: []string{},
		PeerIP:         peerIP,
		OriginASN:      originASN,
		OriginName:     originName,
		RPKIStatus:     rpki,
		Age:            age,
		ValidationNote: note,
	}
}

func (e *Engine) GetNeighborSummary() []models.BGPNeighborSummary {
	settings := e.store.GetSettings()
	views := e.store.GetRouteViews()
	for _, rrNode := range e.store.GetRRNodes() {
		if !rrNode.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rrNode.EngineType), "gobgp") {
			if liveSummaries, ok := e.queryLiveGoBGPNeighbors(context.Background(), rrNode, views); ok && len(liveSummaries) > 0 {
				return liveSummaries
			}
		}
	}

	// If no live GoBGP RR responded, return real Offline / Unreachable state with 0 prefixes (never fake numbers)
	summaries := make([]models.BGPNeighborSummary, 0, len(views))
	for _, v := range views {
		summaries = append(summaries, models.BGPNeighborSummary{
			ViewID:           v.ID,
			ViewName:         v.Name,
			JunosContext:     fmt.Sprintf("%s %s", v.JunosContextType, v.VRFName),
			NeighborIP:       v.JuniperSourceIPv4,
			PeerASN:          settings.PrimaryASN,
			SessionState:     "Offline / Unreachable",
			Uptime:           "-",
			AddPathRx:        true,
			NextHopUnchanged: true,
			PrefixesIPv4:     0,
			PrefixesIPv6:     0,
			UpdatesReceived:  0,
		})
	}
	return summaries
}
