// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	hkgPeer := &apipb.Peer{
		Conf: &apipb.PeerConf{
			NeighborAddress: "192.168.0.46",
			LocalAsn:        65000,
			PeerAsn:         65000,
			Type:            apipb.PeerType_INTERNAL,
			Vrf:             "VRF-CN-OPT",
		},
		State: &apipb.PeerState{
			NeighborAddress: "192.168.0.46",
			LocalAsn:        65000,
			PeerAsn:         65000,
			Type:            apipb.PeerType_INTERNAL,
			SessionState:    apipb.PeerState_ESTABLISHED,
			Messages: &apipb.Messages{
				Received: &apipb.Message{Update: 1500000},
			},
		},
		Timers: &apipb.Timers{
			State: &apipb.TimersState{
				Uptime: timestamppb.New(time.Now().Add(-2 * time.Hour)),
			},
		},
		AfiSafis: []*apipb.AfiSafi{
			{
				AddPaths: &apipb.AddPaths{
					State: &apipb.AddPathsState{Receive: true},
				},
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

	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:        "hkg_cn_opt",
		Name:      "CN Optimized Routing",
		VRFName:   "VRF-CN-OPT",
		Type:      "auto",
		RRNodeIDs: []string{"rr-hkg"},
	})
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

	summaries := eng.GetNeighborSummary()
	if len(summaries) != 3 {
		t.Fatalf("expected 3 neighbor summary rows, got %d: %+v", len(summaries), summaries)
	}
	var cnEst, intlIdleHKG, intlIdleSIN bool
	for _, s := range summaries {
		if s.ViewID == "hkg_cn_opt" && s.RRNodeID == "rr-hkg" && s.SessionState == "Established" &&
			s.PrefixesIPv4 == 1369039 && s.AddPathRx && s.NextHopUnchanged && s.UpdatesReceived == 1500000 {
			cnEst = true
		}
		if s.ViewID == "intl_shared" && s.RRNodeID == "rr-hkg" && s.SessionState == "No Peer / Idle" && !s.AddPathRx {
			intlIdleHKG = true
		}
		if s.ViewID == "intl_shared" && s.RRNodeID == "rr-sin" && s.SessionState == "No Peer / Idle" && !s.AddPathRx {
			intlIdleSIN = true
		}
	}
	if !cnEst || !intlIdleHKG || !intlIdleSIN {
		t.Fatalf("unexpected neighbor summaries: %+v", summaries)
	}

	// Verify VRF->RD cache prevents redundant ListVrf RPCs on consecutive prefix queries
	_, err = eng.ExecuteLookup(context.Background(), models.LookupRequest{
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
	vrfCallsAfterFirst := hkgRR.listVrfCalls.Load()
	_, _ = eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "202.96.134.134",
		Views:     []models.RouteViewID{"hkg_cn_opt"},
		POP:       "HKG4-LG-RR02",
		RRNodeID:  "auto",
		Engine:    "auto",
	})
	if hkgRR.listVrfCalls.Load() != vrfCallsAfterFirst {
		t.Fatalf("expected GoBGP VRF->RD cache hit on second query, but ListVrf increased from %d to %d", vrfCallsAfterFirst, hkgRR.listVrfCalls.Load())
	}
	if sinRR.listPathCalls.Load() != 0 {
		t.Fatalf("strict PoP isolation violated: sin=%d", sinRR.listPathCalls.Load())
	}

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

	hkgBefore := hkgRR.listPathCalls.Load()
	respSIN, err := eng.ExecuteLookup(context.Background(), models.LookupRequest{
		QueryType: "prefix",
		Target:    "202.96.134.133",
		Views:     []models.RouteViewID{"intl_shared"},
		POP:       "SIN-LG-RR02",
		RRNodeID:  "auto",
		Engine:    "auto",
	})
	if err != nil || len(respSIN.Results) != 1 || respSIN.Results[0].RRNodeID != "rr-sin" {
		t.Fatalf("expected SIN lookup to hit rr-sin, err=%v res=%+v", err, respSIN)
	}
	if hkgRR.listPathCalls.Load() != hkgBefore {
		t.Fatalf("HKG RR was unexpectedly touched during SIN lookup!")
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
				TotalPaths:    1,
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
	if len(resp.Results) != 1 || resp.Results[0].MatchedNet != "8.8.8.0/24" || resp.Results[0].TotalPaths != 1 {
		t.Fatalf("unexpected remote agent result: %+v", resp.Results)
	}
}

func TestStreamingFRRJSONAndBird2IPv6TableHelpers(t *testing.T) {
	// 1. Build a large FRR table JSON stream (100 routes) and verify streamFRRTableRoutes stops early at maxRoutes=3
	var sb strings.Builder
	sb.WriteString(`{"vrfId":0,"vrfName":"default","routes":{`)
	for i := 1; i <= 100; i++ {
		if i > 1 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf(`"10.0.%d.0/24":[{"valid":true,"bestpath":true,"locPrf":100,"metric":0,"path":"7720 37965","nexthops":[{"ip":"103.213.4.1","afi":"ipv4"}]}]`, i))
	}
	sb.WriteString(`}}`)

	lines, alive, stoppedEarly := streamFRRTableRoutes(strings.NewReader(sb.String()), "ipv4", 3)
	if !alive || !stoppedEarly || len(lines) != 3 {
		t.Fatalf("expected streaming FRR parser to stop early after 3 routes, got alive=%v early=%v len=%d", alive, stoppedEarly, len(lines))
	}

	// 2. Verify FRR single-prefix JSON object bestpath parsing
	detailJSON := `{"prefix":"139.220.199.0/24","paths":[{"valid":true,"bestpath":{"overall":true},"aspath":{"string":"7720 37965"},"nexthops":[{"ip":"103.213.4.1","afi":"ipv4"}]}]}`
	var detailResp frrPrefixJSONResponse
	if err := json.Unmarshal([]byte(detailJSON), &detailResp); err != nil || !bool(detailResp.Paths[0].Bestpath) {
		t.Fatalf("failed to unmarshal FRR prefix detail JSON: %v", err)
	}

	// 3. Verify unified ^ / $ AS-Path patterns across FRR & BIRD 2
	if got := BuildFRRASPathRegexp("^7720 10111"); got != "^7720_10111_" {
		t.Fatalf("expected ^7720_10111_, got %q", got)
	}
	if got := BuildBird2ASPathPattern("4134$"); got != "[= * 4134 =]" {
		t.Fatalf("expected '[= * 4134 =]', got %q", got)
	}
	if got := BuildBird2ASPathPattern("^2914"); got != "[= 2914 * =]" {
		t.Fatalf("expected '[= 2914 * =]', got %q", got)
	}

	// 4. Verify BIRD 2 Multi-VRF IPv6 table candidate resolution ('LSYS-OPT-v6' & custom BirdTableV6)
	v := models.RouteViewMeta{VRFName: "LSYS-OPT", BirdTableV6: "CUSTOM-OPT-V6"}
	cands := bird2CandidateTables(v, "LSYS-OPT", "ipv6")
	if len(cands) < 2 || cands[0] != "CUSTOM-OPT-V6" || cands[1] != "LSYS-OPT-v6" {
		t.Fatalf("unexpected BIRD 2 IPv6 table candidates: %+v", cands)
	}
}
