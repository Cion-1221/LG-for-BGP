// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const vrfRDCacheTTL = 60 * time.Second

type cachedVrfRD struct {
	rd        string
	expiresAt time.Time
}

type grpcConnPool struct {
	mu      sync.Mutex
	conns   map[string]*grpc.ClientConn
	rdCache map[string]cachedVrfRD
}

var defaultPool = &grpcConnPool{
	conns:   make(map[string]*grpc.ClientConn),
	rdCache: make(map[string]cachedVrfRD),
}

func rdCacheKey(endpoint, vrfName string) string {
	return strings.TrimSpace(endpoint) + "|" + strings.ToLower(strings.TrimSpace(vrfName))
}

func (p *grpcConnPool) setConn(endpoint string, conn *grpc.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ep := strings.TrimSpace(endpoint)
	p.conns[ep] = conn
	p.invalidateEndpointRDsLocked(ep)
}

func (p *grpcConnPool) invalidateEndpointRDsLocked(endpoint string) {
	prefix := strings.TrimSpace(endpoint) + "|"
	for k := range p.rdCache {
		if strings.HasPrefix(k, prefix) {
			delete(p.rdCache, k)
		}
	}
}

func (p *grpcConnPool) closeEndpoint(endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ep := strings.TrimSpace(endpoint)
	if conn, ok := p.conns[ep]; ok {
		_ = conn.Close()
		delete(p.conns, ep)
	}
	p.invalidateEndpointRDsLocked(ep)
}

func (p *grpcConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, conn := range p.conns {
		_ = conn.Close()
		delete(p.conns, k)
	}
	p.rdCache = make(map[string]cachedVrfRD)
}

func (p *grpcConnPool) getCachedRD(endpoint, vrfName string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.rdCache[rdCacheKey(endpoint, vrfName)]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(p.rdCache, rdCacheKey(endpoint, vrfName))
		}
		return "", false
	}
	return entry.rd, true
}

func (p *grpcConnPool) setCachedRD(endpoint, vrfName, rd string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rdCache[rdCacheKey(endpoint, vrfName)] = cachedVrfRD{
		rd:        rd,
		expiresAt: time.Now().Add(vrfRDCacheTTL),
	}
}

// InvalidateVRFRDCache flushes cached GoBGP VRF->RD mappings (called when views/RR nodes or route cache are updated).
func InvalidateVRFRDCache() {
	defaultPool.mu.Lock()
	defaultPool.rdCache = make(map[string]cachedVrfRD)
	defaultPool.mu.Unlock()
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

	ep := strings.TrimSpace(endpoint)
	if conn, ok := p.conns[ep]; ok {
		return apipb.NewGobgpApiClient(conn), nil
	}

	targetURI := ep
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
	p.conns[ep] = conn
	return apipb.NewGobgpApiClient(conn), nil
}

// resolveGoBGPVrfRD resolves a VRF name (e.g. "VRF-CN-OPTIMIZE") to its Route Distinguisher string (e.g. "65000:1"),
// utilizing a short-lived in-memory TTL cache to avoid issuing an extra ListVrf RPC on every prefix lookup.
// For Global RIB queries (`isGlobalRIB(vrfName)`), skips ListVrf entirely unless connectivity needs verification.
func (e *Engine) resolveGoBGPVrfRD(ctx context.Context, client apipb.GobgpApiClient, endpoint, vrfName string) (string, bool) {
	if isGlobalRIB(vrfName) {
		return "", true
	}

	// Direct RD notation entered as VRF name (e.g. "65000:1")
	if _, err := bgp.ParseRouteDistinguisher(strings.TrimSpace(vrfName)); err == nil {
		return strings.TrimSpace(vrfName), true
	}

	if cachedRD, hit := defaultPool.getCachedRD(endpoint, vrfName); hit {
		return cachedRD, true
	}

	stream, err := client.ListVrf(ctx, &apipb.ListVrfRequest{})
	if err != nil {
		return "", false
	}

	matchedRD := ""
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
		// Populate cache for all discovered VRFs on this RR in a single pass
		if vName := strings.TrimSpace(v.GetName()); vName != "" {
			defaultPool.setCachedRD(endpoint, vName, rdStr)
		}
		if strings.EqualFold(strings.TrimSpace(v.GetName()), strings.TrimSpace(vrfName)) || strings.EqualFold(rdStr, strings.TrimSpace(vrfName)) {
			matchedRD = rdStr
		}
	}

	if matchedRD != "" {
		defaultPool.setCachedRD(endpoint, vrfName, matchedRD)
	}
	return matchedRD, true
}
