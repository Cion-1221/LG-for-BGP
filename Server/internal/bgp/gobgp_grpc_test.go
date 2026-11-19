// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

type mockGoBGPServer struct {
	apipb.UnimplementedGobgpApiServer
	vrfName string
	rdStr   string
	lastReq *apipb.ListPathRequest
}

func (m *mockGoBGPServer) ListVrf(_ *apipb.ListVrfRequest, stream apipb.GobgpApi_ListVrfServer) error {
	rdObj, err := bgp.ParseRouteDistinguisher(m.rdStr)
	if err != nil {
		return err
	}
	rdAny, err := apiutil.MarshalRD(rdObj)
	if err != nil {
		return err
	}
	return stream.Send(&apipb.ListVrfResponse{
		Vrf: &apipb.Vrf{
			Name: m.vrfName,
			Rd:   rdAny,
			Id:   1,
		},
	})
}

func (m *mockGoBGPServer) ListPath(req *apipb.ListPathRequest, stream apipb.GobgpApi_ListPathServer) error {
	m.lastReq = req
	// Verify that the driver sends TableType_GLOBAL + SAFI_MPLS_VPN (vpnv4) + Rd + /32 CIDR + SHORTER
	if req.GetTableType() != apipb.TableType_GLOBAL {
		return nil
	}
	if req.GetFamily().GetSafi() != apipb.Family_SAFI_MPLS_VPN {
		return nil
	}
	if len(req.GetPrefixes()) > 0 && req.GetPrefixes()[0].GetRd() != m.rdStr {
		return nil
	}

	rdObj, _ := bgp.ParseRouteDistinguisher(m.rdStr)
	nlri := bgp.NewLabeledVPNIPAddrPrefix(18, "202.96.128.0", *bgp.NewMPLSLabelStack(0), rdObj)

	originIP := net.ParseIP("10.1.9.207")
	clusterIP := net.ParseIP("192.168.0.46")
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeLocalPref(350),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{23764, 4134}),
		}),
		bgp.NewPathAttributeNextHop("172.31.255.10"),
		bgp.NewPathAttributeCommunities([]uint32{(23764 << 16) | 11100, (65535 << 16) | 80}),
		bgp.NewPathAttributeOriginatorId(originIP.String()),
		bgp.NewPathAttributeClusterList([]string{clusterIP.String()}),
	}

	p1, err := apiutil.NewPath(nlri, false, attrs, time.Now().Add(-26*time.Minute))
	if err != nil {
		return err
	}
	p1.Best = true
	p1.NeighborIp = "192.168.0.46"
	if req.GetEnableOnlyBinary() {
		p1.Nlri = nil
		p1.Pattrs = nil
		p1.NlriBinary, _ = nlri.Serialize()
		for _, a := range attrs {
			if b, err := a.Serialize(); err == nil {
				p1.PattrsBinary = append(p1.PattrsBinary, b)
			}
		}
	}

	return stream.Send(&apipb.ListPathResponse{
		Destination: &apipb.Destination{
			Prefix: m.rdStr + ":202.96.128.0/18",
			Paths:  []*apipb.Path{p1},
		},
	})
}

func TestGoBGPgRPCVPNv4VrfLookup(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	mockSrv := &mockGoBGPServer{
		vrfName: "VRF-CN-OPTIMIZE",
		rdStr:   "65000:1",
	}
	grpcServer := grpc.NewServer()
	apipb.RegisterGobgpApiServer(grpcServer, mockSrv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to create bufconn client: %v", err)
	}
	defer conn.Close()
	defaultPool.setConn("bufconn-rr:50051", conn)

	st, err := store.NewAppStore(filepath.Join(t.TempDir(), "test.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	eng := NewEngine(st, security.NewTTLCache())

	rrNode := models.RRNodeConfig{
		ID:         "rr-test",
		Name:       "LG-RR02",
		EngineType: "gobgp",
		LoopbackIP: "127.0.0.1",
		Endpoint:   "bufconn-rr:50051",
		Role:       "primary",
		Enabled:    true,
	}
	view := models.RouteViewMeta{
		ID:                "vrf_cn_optimize",
		Name:              "CN Optimized Routing",
		VRFName:           "VRF-CN-OPTIMIZE",
		Type:              "gobgp",
		JuniperSourceIPv4: "192.168.0.46",
	}

	paths, matched, rawOut, ok := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "prefix", "202.96.134.133")
	if !ok {
		t.Fatalf("expected queryLiveGoBGPgRPC to succeed")
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if matched != "202.96.128.0/18" {
		t.Fatalf("expected matched prefix 202.96.128.0/18, got %s", matched)
	}
	if paths[0].NextHop != "172.31.255.10" {
		t.Fatalf("expected NextHop 172.31.255.10, got %s", paths[0].NextHop)
	}
	if paths[0].ASPathString != "23764 4134" {
		t.Fatalf("expected AS_PATH '23764 4134', got %q", paths[0].ASPathString)
	}
	if paths[0].LocalPref != 350 {
		t.Fatalf("expected LocalPref 350, got %d", paths[0].LocalPref)
	}
	if mockSrv.lastReq.GetPrefixes()[0].GetPrefix() != "202.96.134.133/32" {
		t.Fatalf("expected /32 CIDR lookup prefix, got %s", mockSrv.lastReq.GetPrefixes()[0].GetPrefix())
	}
	t.Logf("Raw output:\n%s", rawOut)

	// Verify AS-Path query ("AS4134" and "23764 4134")
	asPaths, _, _, okAS := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "aspath", "AS4134")
	if !okAS || len(asPaths) != 1 {
		t.Fatalf("expected AS-Path lookup for AS4134 to return 1 path, got %d", len(asPaths))
	}

	// Verify BGP Community query ("23764:11100")
	commPaths, _, _, okComm := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "community", "23764:11100")
	if !okComm || len(commPaths) != 1 {
		t.Fatalf("expected Community lookup for 23764:11100 to return 1 path, got %d", len(commPaths))
	}
}
