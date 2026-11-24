// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"net"
	"path/filepath"
	"strings"
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
	vrfName         string
	rdStr           string
	globalLeakRoute bool
	lastReq         *apipb.ListPathRequest
}

func (m *mockGoBGPServer) ListVrf(_ *apipb.ListVrfRequest, stream apipb.GobgpApi_ListVrfServer) error {
	if m.rdStr == "" {
		return nil
	}
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
	if req.GetTableType() != apipb.TableType_GLOBAL {
		return nil
	}
	if req.GetFamily().GetSafi() == apipb.Family_SAFI_UNICAST {
		if m.globalLeakRoute {
			nlri := bgp.NewIPAddrPrefix(24, "9.9.9.0")
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
				bgp.NewPathAttributeNextHop("192.0.2.99"),
			}
			pGlobal, _ := apiutil.NewPath(nlri, false, attrs, time.Now())
			return stream.Send(&apipb.ListPathResponse{
				Destination: &apipb.Destination{
					Prefix: "9.9.9.0/24",
					Paths:  []*apipb.Path{pGlobal},
				},
			})
		}
		return nil
	}
	if req.GetFamily().GetSafi() != apipb.Family_SAFI_MPLS_VPN {
		return nil
	}
	if len(req.GetPrefixes()) > 0 && req.GetPrefixes()[0].GetRd() != m.rdStr {
		return nil
	}

	rdObj, _ := bgp.ParseRouteDistinguisher(m.rdStr)
	var nlri bgp.AddrPrefixInterface
	var nhAttr bgp.PathAttributeInterface
	var destPrefix string
	if req.GetFamily().GetAfi() == apipb.Family_AFI_IP6 {
		nlri = bgp.NewLabeledVPNIPv6AddrPrefix(32, "240e:100::", *bgp.NewMPLSLabelStack(0), rdObj)
		nhAttr = bgp.NewPathAttributeMpReachNLRI("2001:db8::1", []bgp.AddrPrefixInterface{nlri})
		destPrefix = m.rdStr + ":240e:100::/32"
	} else {
		nlri = bgp.NewLabeledVPNIPAddrPrefix(18, "202.96.128.0", *bgp.NewMPLSLabelStack(0), rdObj)
		nhAttr = bgp.NewPathAttributeNextHop("172.31.255.10")
		destPrefix = m.rdStr + ":202.96.128.0/18"
	}

	originIP := net.ParseIP("10.1.9.207")
	clusterIP := net.ParseIP("192.168.0.46")
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeLocalPref(350),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{23764, 4134}),
		}),
		nhAttr,
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
			Prefix: destPrefix,
			Paths:  []*apipb.Path{p1},
		},
	})
}

func TestGoBGPgRPCVPNv4VrfLookupAndStrictIsolation(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	mockSrv := &mockGoBGPServer{
		vrfName:         "VRF-CN-OPTIMIZE",
		rdStr:           "65000:1",
		globalLeakRoute: true,
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
	defer CloseGRPCConnection("bufconn-rr:50051")

	st, err := store.NewAppStore(filepath.Join(t.TempDir(), "test.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() { _ = st.Close() }()
	cache := security.NewTTLCache()
	defer cache.Close()
	eng := NewEngine(st, cache)

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

	totalPaths, matched, rawOut, ok := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "prefix", "202.96.134.133")
	if !ok || totalPaths != 1 {
		t.Fatalf("expected 1 matched path, got ok=%v total=%d", ok, totalPaths)
	}
	if matched != "202.96.128.0/18" {
		t.Fatalf("expected matched prefix 202.96.128.0/18, got %s", matched)
	}
	for _, token := range []string{"172.31.255.10", "23764 4134", "350"} {
		if !strings.Contains(rawOut, token) {
			t.Fatalf("expected CLI raw_output to contain %q, got:\n%s", token, rawOut)
		}
	}
	if mockSrv.lastReq.GetPrefixes()[0].GetPrefix() != "202.96.134.133/32" {
		t.Fatalf("expected /32 CIDR lookup prefix, got %s", mockSrv.lastReq.GetPrefixes()[0].GetPrefix())
	}

	// Verify IPv6 prefix lookup uses wide IPv6 column headers cleanly
	v6Count, v6Matched, v6Raw, okV6 := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "prefix", "240e:100::1")
	if !okV6 || v6Count != 1 || v6Matched != "240e:100::/32" || !strings.Contains(v6Raw, "2001:db8::1") {
		t.Fatalf("unexpected IPv6 prefix lookup: count=%d matched=%s raw=%s", v6Count, v6Matched, v6Raw)
	}

	// Verify AS-Path anchor semantics (^ and $) on path "23764 4134":
	//  - "^23764" & "4134$" MUST match (2 paths: 1 IPv4 + 1 IPv6)
	//  - "^4134" & "23764$" MUST NOT match (0 paths)
	if cnt, _, _, ok := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "aspath", "^23764"); !ok || cnt != 2 {
		t.Fatalf("expected ^23764 to match 2 dual-stack paths, got %d", cnt)
	}
	if cnt, _, _, ok := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "aspath", "4134$"); !ok || cnt != 2 {
		t.Fatalf("expected 4134$ to match 2 dual-stack paths, got %d", cnt)
	}
	if cnt, _, _, ok := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "aspath", "^4134"); !ok || cnt != 0 {
		t.Fatalf("expected ^4134 NOT to match transit hop 23764->4134, got %d", cnt)
	}
	if cnt, _, _, ok := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "aspath", "23764$"); !ok || cnt != 0 {
		t.Fatalf("expected 23764$ NOT to match non-origin hop 23764->4134, got %d", cnt)
	}

	// Verify BGP Community query ("23764:11100") returns BOTH IPv4 and IPv6 routes
	commCount, _, commRaw, okComm := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, view, "community", "23764:11100")
	if !okComm || commCount != 2 || !strings.Contains(commRaw, "IPv4 Routes") || !strings.Contains(commRaw, "IPv6 Routes") {
		t.Fatalf("expected dual-stack Community lookup to return 2 routes, got %d", commCount)
	}

	// CRITICAL VRF ISOLATION CHECK: Querying an unconfigured VRF ("VRF-NONEXISTENT") MUST NOT leak the Global Unicast route (9.9.9.0/24)!
	unconfiguredView := models.RouteViewMeta{
		ID:      "vrf_missing",
		Name:    "Missing VRF",
		VRFName: "VRF-NONEXISTENT",
		Type:    "gobgp",
	}
	missCount, missMatched, missRaw, okMiss := eng.queryLiveGoBGPgRPC(context.Background(), rrNode, unconfiguredView, "prefix", "9.9.9.9")
	if !okMiss || missCount != 0 || strings.Contains(missRaw, "9.9.9.0/24") {
		t.Fatalf("VRF isolation breach: unconfigured VRF leaked Global RIB route! count=%d matched=%s raw=%s", missCount, missMatched, missRaw)
	}
}
