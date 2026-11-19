// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

const maxConcurrentFullTableScansPerPOP = 3

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
	store    *store.AppStore
	cache    *security.TTLCache
	sfGroup  singleflight.Group
	scanMu   sync.Mutex
	scanSems map[string]chan struct{}
}

func NewEngine(st *store.AppStore, cache *security.TTLCache) *Engine {
	return &Engine{
		store:    st,
		cache:    cache,
		scanSems: make(map[string]chan struct{}),
	}
}

func (e *Engine) getScanSemaphore(popKey string) chan struct{} {
	key := strings.ToLower(strings.TrimSpace(popKey))
	if key == "" {
		key = "_default"
	}
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	if sem, ok := e.scanSems[key]; ok {
		return sem
	}
	sem := make(chan struct{}, maxConcurrentFullTableScansPerPOP)
	e.scanSems[key] = sem
	return sem
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
	out := make([]models.CommunityItem, 0, len(rawList))
	for _, raw := range rawList {
		out = append(out, models.CommunityItem{
			Raw:      raw,
			Label:    raw,
			Category: "community",
		})
	}
	return out
}

func isScopedPOP(pop string) bool {
	p := strings.TrimSpace(pop)
	return p != "" && !strings.EqualFold(p, "all") && !strings.EqualFold(p, "auto") && !strings.EqualFold(p, "multi") && !strings.EqualFold(p, "none")
}

// ViewAllowsRR reports whether the given RouteViewMeta is bound to the given RR node.
// A VRF can bind to 1 RR, multiple RRs, or all RRs (RRNodeIDs = ["all"]).
func ViewAllowsRR(view models.RouteViewMeta, rr models.RRNodeConfig) bool {
	if len(view.RRNodeIDs) == 0 {
		// Unbound VRF or legacy PoP-scoped fallback
		if strings.EqualFold(strings.TrimSpace(view.POP), "none") {
			return false
		}
		if isScopedPOP(view.POP) {
			return strings.EqualFold(strings.TrimSpace(rr.Location), strings.TrimSpace(view.POP))
		}
		return false
	}
	for _, rid := range view.RRNodeIDs {
		trimmed := strings.TrimSpace(rid)
		if strings.EqualFold(trimmed, "all") {
			return true
		}
		if trimmed == rr.ID {
			return true
		}
	}
	return false
}

// ViewBelongsToPOP checks whether a RouteViewMeta has at least one bound enabled RR in targetPOP.
func ViewBelongsToPOP(view models.RouteViewMeta, targetPOP string, rrNodes []models.RRNodeConfig) bool {
	if !isScopedPOP(targetPOP) {
		return true
	}
	for _, rr := range rrNodes {
		if !rr.Enabled || strings.TrimSpace(rr.Endpoint) == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rr.Location), strings.TrimSpace(targetPOP)) {
			continue
		}
		if ViewAllowsRR(view, rr) {
			return true
		}
	}
	return false
}

// selectCandidateRRNodes returns an ordered slice of enabled RR nodes strictly within the requested PoP
// AND bound to the given RouteView (when view != nil).
// It NEVER falls back to RR nodes in other PoPs or unbound RR nodes.
func (e *Engine) selectCandidateRRNodes(requestedID string, requestedPOP string, view *models.RouteViewMeta, requestedEngine string) ([]models.RRNodeConfig, error) {
	nodes := e.store.GetRRNodes()
	var enabledNodes []models.RRNodeConfig
	for _, n := range nodes {
		if n.Enabled && strings.TrimSpace(n.Endpoint) != "" {
			enabledNodes = append(enabledNodes, n)
		}
	}
	if len(enabledNodes) == 0 {
		return nil, fmt.Errorf("no active Route Reflector (RR) node is configured or enabled; please configure at least 1 RR node in the Web Admin Console (Section 3: PoP Groups & RR Nodes)")
	}

	// 1. Strictly filter by requested PoP first — NEVER cross PoP boundaries!
	popFilter := strings.TrimSpace(requestedPOP)
	hasPOPFilter := isScopedPOP(popFilter)
	pool := enabledNodes
	if hasPOPFilter {
		var popNodes []models.RRNodeConfig
		for _, n := range enabledNodes {
			if strings.EqualFold(strings.TrimSpace(n.Location), popFilter) {
				popNodes = append(popNodes, n)
			}
		}
		if len(popNodes) == 0 {
			return nil, fmt.Errorf("no active Route Reflector (RR) node is configured or enabled for PoP %q", popFilter)
		}
		pool = popNodes
	}

	// 2. Strictly filter by VRF <-> RR bindings (if view is specified)
	if view != nil {
		var boundNodes []models.RRNodeConfig
		for _, n := range pool {
			if ViewAllowsRR(*view, n) {
				boundNodes = append(boundNodes, n)
			}
		}
		if len(boundNodes) == 0 {
			if hasPOPFilter {
				return nil, fmt.Errorf("route view %q is not bound to any active RR node in PoP %q", view.ID, popFilter)
			}
			return nil, fmt.Errorf("route view %q is not bound to any active RR node", view.ID)
		}
		pool = boundNodes
	}

	// 3. Explicit RR node ID check within strictly filtered pool
	reqID := strings.TrimSpace(requestedID)
	if reqID != "" && !strings.EqualFold(reqID, "auto") {
		for _, n := range pool {
			if n.ID == reqID {
				return []models.RRNodeConfig{n}, nil
			}
		}
		if hasPOPFilter {
			return nil, fmt.Errorf("selected Route Reflector (RR) node %q is not found, disabled, not bound to this VRF, or does not belong to PoP %q", reqID, popFilter)
		}
		return nil, fmt.Errorf("selected Route Reflector (RR) node %q is not found, disabled, or not bound to this VRF", reqID)
	}

	eng := strings.ToLower(strings.TrimSpace(requestedEngine))
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

	// Priority strictly inside this PoP & VRF's bound RRs: Primary -> Backup
	addMatching(true, true)
	addMatching(true, false)
	addMatching(false, true)
	addMatching(false, false)

	return candidates, nil
}

func (e *Engine) ExecuteLookup(ctx context.Context, req models.LookupRequest) (*models.LookupResponse, error) {
	settings := e.store.GetSettings()
	reqPOP := strings.TrimSpace(req.POP)
	hasReqPOP := isScopedPOP(reqPOP)
	allRRs := e.store.GetRRNodes()

	viewMap := e.store.GetRouteViewMap()
	if hasReqPOP {
		for _, viewID := range req.Views {
			vm, ok := viewMap[viewID]
			if !ok {
				continue
			}
			if !ViewBelongsToPOP(vm, reqPOP, allRRs) {
				return nil, fmt.Errorf("route view %q is not bound to any active RR node in PoP %q", vm.ID, reqPOP)
			}
		}
	}

	baseCandidates, err := e.selectCandidateRRNodes(req.RRNodeID, reqPOP, nil, req.Engine)
	if err != nil {
		return nil, err
	}
	primaryRR := baseCandidates[0]
	engineUsed := req.Engine
	if engineUsed == "" || engineUsed == "auto" {
		engineUsed = primaryRR.EngineType
	}

	results := make([]models.ViewQueryResult, len(req.Views))
	var wg sync.WaitGroup

	ttl := time.Duration(settings.CacheTTLSeconds) * time.Second
	isFullTableScan := req.QueryType == "aspath" || req.QueryType == "community"

	for idx, viewID := range req.Views {
		viewMeta, ok := viewMap[viewID]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(i int, vm models.RouteViewMeta) {
			defer wg.Done()

			// Enforce strict PoP + VRF->RR binding
			targetPOP := reqPOP
			if !hasReqPOP && isScopedPOP(vm.POP) {
				targetPOP = strings.TrimSpace(vm.POP)
			}

			candidates, errCand := e.selectCandidateRRNodes(req.RRNodeID, targetPOP, &vm, req.Engine)
			if errCand != nil || len(candidates) == 0 {
				errMsg := "no active bound Route Reflector (RR) node available for this PoP"
				if errCand != nil {
					errMsg = errCand.Error()
				}
				results[i] = models.ViewQueryResult{
					View:        vm,
					EngineType:  vm.Type,
					QueryTarget: req.Target,
					MatchedNet:  "No Active RR in PoP",
					TotalPaths:  0,
					Paths:       []models.BGPRoutePath{},
					RawOutput:   fmt.Sprintf("# Error: %s\n", errMsg),
					QueryTimeMs: 1,
				}
				return
			}

			preferredEngine := strings.ToLower(strings.TrimSpace(candidates[0].EngineType))
			if req.Engine != "" && !strings.EqualFold(req.Engine, "auto") {
				preferredEngine = strings.ToLower(strings.TrimSpace(req.Engine))
			}

			cacheKey := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
				candidates[0].ID,
				strings.ToLower(strings.TrimSpace(targetPOP)),
				preferredEngine,
				req.QueryType,
				req.Target,
				vm.ID,
				vm.VRFName,
			)
			if cachedRes, hit := e.cache.Get(cacheKey); hit {
				results[i] = cachedRes
				return
			}

			// Singleflight deduplicates concurrent identical queries to protect the RR
			sfVal, _, _ := e.sfGroup.Do(cacheKey, func() (interface{}, error) {
				// Re-check cache after entering singleflight
				if cachedRes, hit := e.cache.Get(cacheKey); hit {
					return cachedRes, nil
				}

				// Concurrency gate for expensive full-table scans (aspath / community) per PoP
				if isFullTableScan {
					semKey := targetPOP
					if semKey == "" {
						semKey = candidates[0].Location
					}
					sem := e.getScanSemaphore(semKey)
					waitTimer := time.NewTimer(5 * time.Second)
					select {
					case sem <- struct{}{}:
						waitTimer.Stop()
						defer func() { <-sem }()
					case <-waitTimer.C:
						return models.ViewQueryResult{
							View:        vm,
							RRNodeID:    candidates[0].ID,
							RRNodeName:  candidates[0].Name,
							EngineType:  preferredEngine,
							QueryTarget: req.Target,
							MatchedNet:  "Scan Concurrency Limit",
							TotalPaths:  0,
							Paths:       []models.BGPRoutePath{},
							RawOutput:   fmt.Sprintf("# Busy: PoP %s full-table scan concurrency limit (%d) reached; please retry in a few seconds.\n", semKey, maxConcurrentFullTableScansPerPOP),
							QueryTimeMs: 1,
						}, nil
					case <-ctx.Done():
						waitTimer.Stop()
						return models.ViewQueryResult{
							View:        vm,
							RRNodeID:    candidates[0].ID,
							RRNodeName:  candidates[0].Name,
							EngineType:  preferredEngine,
							QueryTarget: req.Target,
							MatchedNet:  "Request Cancelled",
							TotalPaths:  0,
							Paths:       []models.BGPRoutePath{},
							RawOutput:   "# Request cancelled by client.\n",
							QueryTimeMs: 1,
						}, nil
					}
				}

				start := time.Now()
				res := e.querySingleViewWithFailover(ctx, candidates, req.Engine, vm, req.QueryType, req.Target)
				res.QueryTimeMs = time.Since(start).Milliseconds()
				if res.QueryTimeMs == 0 {
					res.QueryTimeMs = 1
				}
				if res.MatchedNet != "RR Connection Failed" &&
					res.MatchedNet != "No Active RR in PoP" &&
					res.MatchedNet != "Scan Concurrency Limit" &&
					res.MatchedNet != "Request Cancelled" {
					e.cache.Set(cacheKey, res, ttl)
				}
				return res, nil
			})

			results[i] = sfVal.(models.ViewQueryResult)
		}(idx, viewMeta)
	}
	wg.Wait()

	usedRRDisplay := primaryRR.Name
	if len(results) > 0 && results[0].RRNodeID != "" {
		for _, n := range allRRs {
			if n.ID == results[0].RRNodeID {
				usedRRDisplay = n.Name
				if results[0].EngineType != "" {
					engineUsed = results[0].EngineType
				}
				break
			}
		}
	}

	return &models.LookupResponse{
		QueryType:  req.QueryType,
		Target:     req.Target,
		RRNodeUsed: usedRRDisplay,
		EngineUsed: strings.ToUpper(engineUsed),
		Timestamp:  time.Now(),
		Results:    results,
	}, nil
}

// querySingleViewWithFailover queries 1 or multiple bound RR nodes strictly within the same PoP (Primary -> Backup).
// Each RR is queried using that RR's own configured EngineType (unless reqEngine overrides it explicitly).
func (e *Engine) querySingleViewWithFailover(
	ctx context.Context,
	candidates []models.RRNodeConfig,
	reqEngine string,
	view models.RouteViewMeta,
	queryType string,
	target string,
) models.ViewQueryResult {
	for _, rrNode := range candidates {
		activeEngine := strings.ToLower(strings.TrimSpace(rrNode.EngineType))
		if reqEngine != "" && !strings.EqualFold(reqEngine, "auto") {
			activeEngine = strings.ToLower(strings.TrimSpace(reqEngine))
		}
		if activeEngine == "" {
			activeEngine = strings.ToLower(strings.TrimSpace(view.Type))
		}
		if activeEngine == "" || activeEngine == "auto" {
			activeEngine = "gobgp"
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
	failEng := strings.ToUpper(rrNode.EngineType)
	errRaw := fmt.Sprintf("# Error: Unable to query Route Reflector %s [PoP: %s] (%s).\n# The collector node is temporarily unreachable. Please retry shortly or contact the network operator.\n",
		rrNode.Name, rrNode.Location, failEng)

	return models.ViewQueryResult{
		View:        view,
		RRNodeID:    rrNode.ID,
		RRNodeName:  rrNode.Name,
		EngineType:  rrNode.EngineType,
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

// GetNeighborSummary queries EVERY enabled RR node (GoBGP gRPC, BIRD 2, and FRR — local or remote lg-agent)
// strictly for the VRFs bound to that RR node. Each row identifies its PoP, RR Node, Engine, Route View, and VRF,
// so multiple RRs sharing the same VRF name are displayed distinctly and accurately, and VRFs with no BGP peer
// honestly report "No Peer / Idle" instead of borrowing another VRF's peer data.
func (e *Engine) GetNeighborSummary() []models.BGPNeighborSummary {
	views := e.store.GetRouteViews()
	rrNodes := e.store.GetRRNodes()

	// Group bound views per enabled RR so each RR is queried ONCE in parallel
	type rrJob struct {
		node  models.RRNodeConfig
		views []models.RouteViewMeta
	}
	var jobs []rrJob
	boundViewHasRR := make(map[models.RouteViewID]bool)

	for _, rr := range rrNodes {
		if !rr.Enabled || strings.TrimSpace(rr.Endpoint) == "" {
			continue
		}
		var rrViews []models.RouteViewMeta
		for _, v := range views {
			if ViewAllowsRR(v, rr) {
				rrViews = append(rrViews, v)
				boundViewHasRR[v.ID] = true
			}
		}
		if len(rrViews) > 0 {
			jobs = append(jobs, rrJob{node: rr, views: rrViews})
		}
	}

	perJobResults := make([][]models.BGPNeighborSummary, len(jobs))
	var wg sync.WaitGroup
	for idx, job := range jobs {
		wg.Add(1)
		go func(i int, j rrJob) {
			defer wg.Done()
			ctx := context.Background()
			engType := strings.ToLower(strings.TrimSpace(j.node.EngineType))
			var (
				res []models.BGPNeighborSummary
				ok  bool
			)
			switch engType {
			case "gobgp":
				res, ok = e.queryLiveGoBGPNeighbors(ctx, j.node, j.views)
			case "bird2":
				res, ok = e.queryLiveBird2Neighbors(ctx, j.node, j.views)
			case "frr":
				res, ok = e.queryLiveFrrNeighbors(ctx, j.node, j.views)
			}

			if ok {
				perJobResults[i] = res
				return
			}

			// RR node unreachable -> emit explicit RR Unreachable rows for each VRF bound to this RR
			offline := make([]models.BGPNeighborSummary, 0, len(j.views))
			for _, v := range j.views {
				offline = append(offline, models.BGPNeighborSummary{
					POP:          j.node.Location,
					RRNodeID:     j.node.ID,
					RRNodeName:   j.node.Name,
					EngineType:   engType,
					ViewID:       v.ID,
					ViewName:     v.Name,
					VRFName:      v.VRFName,
					JunosContext: fmt.Sprintf("%s %s", v.JunosContextType, v.VRFName),
					NeighborIP:   strings.TrimSpace(v.JuniperSourceIPv4),
					SessionState: "RR Unreachable",
					Uptime:       "-",
				})
			}
			perJobResults[i] = offline
		}(idx, job)
	}
	wg.Wait()

	var summaries []models.BGPNeighborSummary
	for _, list := range perJobResults {
		summaries = append(summaries, list...)
	}

	// Include any configured VRFs that currently have 0 active bound RRs so admin can spot misconfigurations
	for _, v := range views {
		if !boundViewHasRR[v.ID] {
			summaries = append(summaries, models.BGPNeighborSummary{
				POP:          v.POP,
				RRNodeID:     "",
				RRNodeName:   "(Unbound)",
				EngineType:   v.Type,
				ViewID:       v.ID,
				ViewName:     v.Name,
				VRFName:      v.VRFName,
				JunosContext: fmt.Sprintf("%s %s", v.JunosContextType, v.VRFName),
				NeighborIP:   strings.TrimSpace(v.JuniperSourceIPv4),
				SessionState: "No Bound RR",
				Uptime:       "-",
			})
		}
	}

	return summaries
}
