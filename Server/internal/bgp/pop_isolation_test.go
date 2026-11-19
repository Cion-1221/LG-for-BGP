// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

type countingGoBGPServer struct {
	mockGoBGPServer
	listPathCalls atomic.Int32
	listVrfCalls  atomic.Int32
	peers         []*apipb.Peer
}

func (c *countingGoBGPServer) ListVrf(req *apipb.ListVrfRequest, stream apipb.GobgpApi_ListVrfServer) error {
	c.listVrfCalls.Add(1)
	return c.mockGoBGPServer.ListVrf(req, stream)
}

func (c *countingGoBGPServer) ListPath(req *apipb.ListPathRequest, stream apipb.GobgpApi_ListPathServer) error {
	c.listPathCalls.Add(1)
	return c.mockGoBGPServer.ListPath(req, stream)
}

func (c *countingGoBGPServer) ListPeer(_ *apipb.ListPeerRequest, stream apipb.GobgpApi_ListPeerServer) error {
	for _, p := range c.peers {
		if err := stream.Send(&apipb.ListPeerResponse{Peer: p}); err != nil {
			return err
		}
	}
	return nil
}

func startCountingMockRR(t *testing.T, endpoint, vrfName, rdStr string, peers []*apipb.Peer) (*countingGoBGPServer, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := &countingGoBGPServer{
		mockGoBGPServer: mockGoBGPServer{
			vrfName: vrfName,
			rdStr:   rdStr,
		},
		peers: peers,
	}
	grpcServer := grpc.NewServer()
	apipb.RegisterGobgpApiServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		grpcServer.Stop()
		_ = lis.Close()
		t.Fatalf("failed to create bufconn client: %v", err)
	}
	defaultPool.setConn(endpoint, conn)
	cleanup := func() {
		CloseGRPCConnection(endpoint)
		grpcServer.Stop()
		_ = lis.Close()
	}
	return srv, cleanup
}

func TestStrictSinglePoPRRIsolationAndAccurateNeighbors(t *testing.T) {
	// HKG RR only has 1 Established peer in VRF-CN-OPT (NO peer for VRF-INTL-ROUTING!)
	hkgPeer := &apipb.Peer{
		Conf: &apipb.PeerConf{
			NeighborAddress: "192.168.0.46",
			PeerAsn:         18913,
			Vrf:             "VRF-CN-OPT",
		},
		State: &apipb.PeerState{
			NeighborAddress: "192.168.0.46",
			PeerAsn:         18913,
			SessionState:    apipb.PeerState_ESTABLISHED,
		},
		Timers: &apipb.Timers{
			State: &apipb.TimersState{
				Uptime: timestamppb.New(time.Now().Add(-2 * time.Hour)),
			},
		},
		AfiSafis: []*apipb.AfiSafi{
			{
				State: &apipb.AfiSafiState{
					Family:   &apipb.Family{Afi: apipb.Family_AFI_IP, Safi: apipb.Family_SAFI_UNICAST},
					Accepted: 1369039,
					Received: 1369039,
				},
			},
		},
	}

	hkgRR, cleanupHKG := startCountingMockRR(t, "bufconn-hkg:50051", "VRF-CN-OPT", "18913:1", []*apipb.Peer{hkgPeer})
	defer cleanupHKG()
	sinRR, cleanupSIN := startCountingMockRR(t, "bufconn-sin:50051", "VRF-SIN", "18913:2", nil)
	defer cleanupSIN()

	st, err := store.NewAppStore(filepath.Join(t.TempDir(), "pop_iso.db"))
	if err != nil {
		t.Fatalf("failed to init sqlite store: %v", err)
	}
	defer func() { _ = st.Close() }()

	_ = st.UpsertPOP(models.POPGroup{ID: "HKG4-LG-RR02", Name: "HKG", SortOrder: 1})
	_ = st.UpsertPOP(models.POPGroup{ID: "SIN-LG-RR02", Name: "SIN", SortOrder: 2})

	_ = st.UpsertRRNode(models.RRNodeConfig{
		ID:         "rr-hkg",
		Name:       "HKG4-LG-RR02",
		Location:   "HKG4-LG-RR02",
		EngineType: "gobgp",
		LoopbackIP: "10.1.0.1",
		Endpoint:   "bufconn-hkg:50051",
		Role:       "primary",
		Enabled:    true,
	})
	_ = st.UpsertRRNode(models.RRNodeConfig{
		ID:         "rr-sin",
		Name:       "SIN-LG-RR02",
		Location:   "SIN-LG-RR02",
		EngineType: "gobgp",
		LoopbackIP: "10.2.0.1",
		Endpoint:   "bufconn-sin:50051",
		Role:       "primary",
		Enabled:    true,
	})

	// VRF 1: bound ONLY to rr-hkg
	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:        "hkg_cn_opt",
		Name:      "CN Optimized Routing",
		VRFName:   "VRF-CN-OPT",
		Type:      "auto",
		RRNodeIDs: []string{"rr-hkg"},
	})
	// VRF 2: bound to BOTH rr-hkg and rr-sin (has NO established BGP peer on either!)
	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:        "intl_shared",
		Name:      "INTL Routing",
		VRFName:   "VRF-INTL-ROUTING",
		Type:      "auto",
		RRNodeIDs: []string{"rr-hkg", "rr-sin"},
	})

	cache := security.NewTTLCache()
	defer cache.Close()
	eng := NewEngine(st, cache)

	// 1. Verify GetNeighborSummary accurately isolates peers per (RR, VRF) and NEVER borrows VRF-CN-OPT's peer for VRF-INTL-ROUTING!
	summaries := eng.GetNeighborSummary()
	if len(summaries) != 3 {
		t.Fatalf("expected 3 neighbor summary rows (1 for hkg_cn_opt + 2 for intl_shared across rr-hkg & rr-sin), got %d: %+v", len(summaries), summaries)
	}
	var cnEst, intlIdleHKG, intlIdleSIN bool
	for _, s := range summaries {
		if s.ViewID == "hkg_cn_opt" && s.RRNodeID == "rr-hkg" && s.SessionState == "Established" && s.PrefixesIPv4 == 1369039 {
			cnEst = true
		}
		if s.ViewID == "intl_shared" && s.RRNodeID == "rr-hkg" && s.SessionState == "No Peer / Idle" && s.PrefixesIPv4 == 0 {
			intlIdleHKG = true
		}
		if s.ViewID == "intl_shared" && s.RRNodeID == "rr-sin" && s.SessionState == "No Peer / Idle" && s.PrefixesIPv4 == 0 {
			intlIdleSIN = true
		}
	}
	if !cnEst || !intlIdleHKG || !intlIdleSIN {
		t.Fatalf("unexpected neighbor summaries (must not borrow peers across VRFs): %+v", summaries)
	}

	// 2. Querying HKG MUST ONLY touch HKG RR, NEVER SIN RR
	respHKG, err := eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "202.96.134.133",
		Views:     []models.RouteViewID{"hkg_cn_opt"},
		POP:       "HKG4-LG-RR02",
		RRNodeID:  "auto",
		Engine:    "auto",
	})
	if err != nil {
		t.Fatalf("HKG lookup failed: %v", err)
	}
	if len(respHKG.Results) != 1 || respHKG.Results[0].RRNodeID != "rr-hkg" {
		t.Fatalf("expected result from rr-hkg, got %+v", respHKG.Results)
	}
	if hkgRR.listPathCalls.Load() == 0 || sinRR.listPathCalls.Load() != 0 {
		t.Fatalf("strict PoP isolation violated: hkg=%d sin=%d", hkgRR.listPathCalls.Load(), sinRR.listPathCalls.Load())
	}

	// 3. Querying SIN with HKG-only VRF MUST be rejected
	if _, err := eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "202.96.134.133",
		Views:     []models.RouteViewID{"hkg_cn_opt"},
		POP:       "SIN-LG-RR02",
		RRNodeID:  "auto",
		Engine:    "auto",
	}); err == nil {
		t.Fatalf("expected error when querying HKG-only VRF under SIN PoP")
	}

	// 4. Querying SIN with shared VRF (bound to rr-hkg + rr-sin) MUST ONLY hit rr-sin!
	hkgBefore := hkgRR.listPathCalls.Load()
	respSIN, err := eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "202.96.134.133",
		Views:     []models.RouteViewID{"intl_shared"},
		POP:       "SIN-LG-RR02",
		RRNodeID:  "auto",
		Engine:    "auto",
	})
	if err != nil {
		t.Fatalf("SIN lookup on shared VRF failed: %v", err)
	}
	if len(respSIN.Results) != 1 || respSIN.Results[0].RRNodeID != "rr-sin" {
		t.Fatalf("expected SIN lookup to hit rr-sin, got %+v", respSIN.Results)
	}
	if hkgRR.listPathCalls.Load() != hkgBefore {
		t.Fatalf("HKG RR was unexpectedly touched during SIN lookup!")
	}

	// 5. Disable SIN RR -> querying SIN MUST FAIL and MUST NOT fall back to HKG RR!
	_ = st.UpsertRRNode(models.RRNodeConfig{
		ID:         "rr-sin",
		Name:       "SIN-LG-RR02",
		Location:   "SIN-LG-RR02",
		EngineType: "gobgp",
		LoopbackIP: "10.2.0.1",
		Endpoint:   "bufconn-sin:50051",
		Role:       "primary",
		Enabled:    false,
	})
	hkgBefore = hkgRR.listPathCalls.Load()
	if _, err := eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "202.96.134.133",
		Views:     []models.RouteViewID{"intl_shared"},
		POP:       "SIN-LG-RR02",
		RRNodeID:  "auto",
		Engine:    "auto",
	}); err == nil {
		t.Fatalf("expected error when SIN RR is disabled, MUST NOT fall back to HKG RR")
	}
	if hkgRR.listPathCalls.Load() != hkgBefore {
		t.Fatalf("HKG RR was unexpectedly queried as fallback when SIN RR was disabled!")
	}
}

func TestRemoteLGAgentFRRQueryAndProbe(t *testing.T) {
	const expectedToken = "secret-agent-token"
	mockAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expectedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/agent/v1/health":
			_ = json.NewEncoder(w).Encode(AgentHealthResponse{Status: "ok", Engine: "frr", Message: "FRR ready"})
		case "/agent/v1/query":
			_ = json.NewEncoder(w).Encode(AgentQueryResponse{
				OK:            true,
				MatchedPrefix: "8.8.8.0/24",
				Paths:         []models.BGPRoutePath{{Prefix: "8.8.8.0/24", NextHop: "10.9.9.1", Best: true}},
				RawOutput:     "*> 8.8.8.0/24 10.9.9.1 15169 i\n",
			})
		}
	}))
	defer mockAgent.Close()

	health, err := ProbeRemoteAgent(context.Background(), mockAgent.URL, expectedToken)
	if err != nil || health.Status != "ok" {
		t.Fatalf("ProbeRemoteAgent failed: err=%v health=%+v", err, health)
	}

	st, _ := store.NewAppStore("memory")
	defer func() { _ = st.Close() }()
	_ = st.UpsertRRNode(models.RRNodeConfig{
		ID:         "rr-vyos",
		Name:       "VYOS-FRR-01",
		Location:   "SIN-POP",
		EngineType: "frr",
		LoopbackIP: "10.9.9.9",
		Endpoint:   mockAgent.URL,
		AgentToken: expectedToken,
		Role:       "primary",
		Enabled:    true,
	})
	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:        "vyos_global",
		Name:      "VyOS Global",
		VRFName:   "global",
		Type:      "auto",
		RRNodeIDs: []string{"rr-vyos"},
	})

	cache := security.NewTTLCache()
	defer cache.Close()
	eng := NewEngine(st, cache)

	resp, err := eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "8.8.8.8",
		Views:     []models.RouteViewID{"vyos_global"},
		POP:       "SIN-POP",
		RRNodeID:  "auto",
		Engine:    "auto",
	})
	if err != nil {
		t.Fatalf("remote lg-agent lookup failed: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].MatchedNet != "8.8.8.0/24" || resp.Results[0].EngineType != "frr" {
		t.Fatalf("unexpected remote agent result: %+v", resp.Results)
	}
}

func TestFRRJSONParsingTableAndDetailFormats(t *testing.T) {
	st, _ := store.NewAppStore("memory")
	defer func() { _ = st.Close() }()
	cache := security.NewTTLCache()
	defer cache.Close()
	eng := NewEngine(st, cache)

	// 1. Real FRR 10.7.1 `show bgp ipv4 unicast regexp _37965_ json` / `community ... json` output:
	//    Note `"bestpath": true` (JSON bool), top-level `"path"`, and top-level `"peerId"`!
	tableJSON := `{
		"vrfId": 0,
		"vrfName": "default",
		"tableVersion": 17827814,
		"routerId": "103.213.4.23",
		"defaultLocPrf": 100,
		"localAS": 65000,
		"routes": {
			"139.220.199.0/24": [
				{
					"valid": true,
					"bestpath": true,
					"selectionReason": "First path received",
					"pathFrom": "external",
					"prefix": "139.220.199.0",
					"prefixLen": 24,
					"network": "139.220.199.0/24",
					"metric": 0,
					"locPrf": 100,
					"weight": 0,
					"peerId": "103.213.4.1",
					"path": "7720 10111 4637 7468 37965",
					"origin": "IGP",
					"nexthops": [
						{"ip": "103.213.4.1", "afi": "ipv4", "used": true}
					]
				}
			]
		}
	}`
	var tableResp frrTableJSONResponse
	if err := json.Unmarshal([]byte(tableJSON), &tableResp); err != nil {
		t.Fatalf("failed to unmarshal FRR table-scan JSON (bool bestpath): %v", err)
	}
	view := models.RouteViewMeta{ID: "intl", Name: "INTL-ROUTING", VRFName: "global"}
	paths := eng.convertFRRPaths("139.220.199.0/24", "ipv4", "global", view, tableResp.Routes["139.220.199.0/24"])
	if len(paths) != 1 || !paths[0].Best || paths[0].NextHop != "103.213.4.1" || paths[0].PeerIP != "103.213.4.1" || paths[0].OriginASN != 37965 {
		t.Fatalf("unexpected converted FRR table path: %+v", paths)
	}

	// 2. Real FRR `show bgp ipv4 unicast <prefix> json` detail output:
	//    Note `"bestpath": {"overall": true}` (JSON object), `"aspath": {"string": ...}`, and `"peer": {"peerId": ...}`!
	detailJSON := `{
		"prefix": "139.220.199.0/24",
		"paths": [
			{
				"valid": true,
				"bestpath": {"overall": true},
				"aspath": {"string": "7720 10111 4637 7468 37965"},
				"peer": {"peerId": "103.213.4.1"},
				"nexthops": [{"ip": "103.213.4.1", "afi": "ipv4"}],
				"community": {"list": ["7720:1000"]}
			}
		]
	}`
	var detailResp frrPrefixJSONResponse
	if err := json.Unmarshal([]byte(detailJSON), &detailResp); err != nil {
		t.Fatalf("failed to unmarshal FRR prefix detail JSON (object bestpath): %v", err)
	}
	dPaths := eng.convertFRRPaths(detailResp.Prefix, "ipv4", "global", view, detailResp.Paths)
	if len(dPaths) != 1 || !dPaths[0].Best || dPaths[0].OriginASN != 37965 || len(dPaths[0].Communities) != 1 {
		t.Fatalf("unexpected converted FRR detail path: %+v", dPaths)
	}

	// 3. Verify AS-Path regex builder preserves optional ^ / $ anchors safely
	if got := buildFRRASPathRegexp("37965"); got != "_37965_" {
		t.Fatalf("expected _37965_, got %q", got)
	}
	if got := buildFRRASPathRegexp("_37965$"); got != "_37965$" {
		t.Fatalf("expected _37965$, got %q", got)
	}
	if got := buildFRRASPathRegexp("^7720 10111"); got != "^7720_10111_" {
		t.Fatalf("expected ^7720_10111_, got %q", got)
	}
}
