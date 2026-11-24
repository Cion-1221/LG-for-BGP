// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package api

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

type Server struct {
	store             *store.AppStore
	engine            *bgp.Engine
	cache             *security.TTLCache
	rateLimiter       *security.RateLimiter
	loginGuard        *security.LoginGuard
	staticDir         string
	accessLog         bool
	trustedProxyAddrs map[netip.Addr]bool
	trustedProxyCIDRs []netip.Prefix
	allowedOrigins    []string
}

func NewServer(st *store.AppStore, eng *bgp.Engine, cache *security.TTLCache, staticDir string, trustedProxies ...string) *Server {
	s := &Server{
		store:             st,
		engine:            eng,
		cache:             cache,
		rateLimiter:       security.NewRateLimiter(),
		loginGuard:        security.NewLoginGuard(5, 15*time.Minute, 15*time.Minute),
		staticDir:         staticDir,
		accessLog:         true,
		trustedProxyAddrs: make(map[netip.Addr]bool),
	}

	rawList := trustedProxies
	if len(rawList) == 0 {
		rawList = []string{"127.0.0.1", "::1"}
	}
	for _, entry := range rawList {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			if pfx, err := netip.ParsePrefix(trimmed); err == nil {
				s.trustedProxyCIDRs = append(s.trustedProxyCIDRs, pfx.Masked())
			}
		} else if addr, err := netip.ParseAddr(trimmed); err == nil {
			s.trustedProxyAddrs[addr.Unmap()] = true
		}
	}

	return s
}

func (s *Server) SetAccessLog(enabled bool) {
	s.accessLog = enabled
}

func (s *Server) SetAllowedOrigins(origins []string) {
	s.allowedOrigins = origins
}

func (s *Server) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	if s.loginGuard != nil {
		s.loginGuard.Close()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/bootstrap", s.handleBootstrap)
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/change-password", s.handleChangePassword)
	mux.HandleFunc("/api/v1/auth/me", s.handleMe)

	mux.HandleFunc("/api/v1/bgp/lookup", s.handleBGPLookup)
	mux.HandleFunc("/api/v1/bgp/summary", s.handleBGPSummary)

	mux.HandleFunc("/api/v1/admin/settings", s.handleAdminSettings)
	mux.HandleFunc("/api/v1/admin/views", s.handleAdminViews)
	mux.HandleFunc("/api/v1/admin/pops", s.handleAdminPOPs)
	mux.HandleFunc("/api/v1/admin/rr-nodes", s.handleAdminRRNodes)
	mux.HandleFunc("/api/v1/admin/rr-nodes/probe", s.handleAdminProbeRRNode)
	mux.HandleFunc("/api/v1/admin/users", s.handleAdminUsers)
	mux.HandleFunc("/api/v1/admin/audit-logs", s.handleAdminAuditLogs)
	mux.HandleFunc("/api/v1/admin/security/locks", s.handleAdminSecurityLocks)
	mux.HandleFunc("/api/v1/admin/cache/clear", s.handleAdminClearCache)

	mux.HandleFunc("/", s.handleStaticUI)

	return s.corsMiddleware(mux)
}
