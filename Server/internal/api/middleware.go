// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package api

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
)

const defaultMaxAPIBodyBytes = 64 * 1024 // 64 KB default JSON payload cap (settings endpoint overrides to 1 MB)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) corsOriginFor(origin string) string {
	if len(s.allowedOrigins) == 0 {
		return "*"
	}
	for _, allowed := range s.allowedOrigins {
		a := strings.TrimSpace(allowed)
		if a == "*" {
			return "*"
		}
		if origin != "" && strings.EqualFold(a, origin) {
			return origin
		}
	}
	return ""
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if originHeader := s.corsOriginFor(r.Header.Get("Origin")); originHeader != "" {
			w.Header().Set("Access-Control-Allow-Origin", originHeader)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Enforce bounded request body sizes on all API mutations (settings uses 1 MB for icons)
		if r.Body != nil && r.URL.Path != "/api/v1/admin/settings" &&
			(r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			r.Body = http.MaxBytesReader(w, r.Body, defaultMaxAPIBodyBytes)
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if s.accessLog {
			slog.Info("http_access",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"client_ip", s.clientIP(r),
				"duration_ms", time.Since(start).Milliseconds(),
				"user_agent", r.UserAgent(),
			)
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{
		"error":     msg,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func (s *Server) isTrustedProxyAddr(addr netip.Addr) bool {
	unmapped := addr.Unmap()
	if s.trustedProxyAddrs[unmapped] {
		return true
	}
	for _, pfx := range s.trustedProxyCIDRs {
		if pfx.Contains(unmapped) {
			return true
		}
	}
	return false
}

// clientIP extracts the authentic client IP address while defending against X-Forwarded-For spoofing.
// When the TCP peer is a configured trusted proxy (e.g. local Nginx / Apache / Caddy), X-Forwarded-For is
// walked RIGHT-TO-LEFT, skipping trusted proxy hops and returning the rightmost untrusted IP address.
func (s *Server) clientIP(r *http.Request) string {
	remoteHost := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(remoteHost); err == nil {
		remoteHost = h
	}
	remoteAddr, errRemote := netip.ParseAddr(remoteHost)
	if errRemote != nil || !s.isTrustedProxyAddr(remoteAddr) {
		return remoteHost
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		var lastValidTrusted string
		for i := len(parts) - 1; i >= 0; i-- {
			cand := strings.TrimSpace(parts[i])
			if cand == "" {
				continue
			}
			addr, err := netip.ParseAddr(cand)
			if err != nil {
				continue
			}
			normalized := addr.Unmap().String()
			if !s.isTrustedProxyAddr(addr) {
				return normalized
			}
			if lastValidTrusted == "" {
				lastValidTrusted = normalized
			}
		}
		if lastValidTrusted != "" {
			return lastValidTrusted
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if addr, err := netip.ParseAddr(xri); err == nil {
			return addr.Unmap().String()
		}
	}

	return remoteAddr.Unmap().String()
}

func (s *Server) currentUser(r *http.Request) *models.UserAccount {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token == "" {
		return nil
	}
	u, err := s.store.VerifyToken(token)
	if err != nil {
		return nil
	}
	return u
}

func (s *Server) resolveAccess(r *http.Request) (user *models.UserAccount, allowedViews []models.RouteViewID, rateLimit int, errMsg string, status int) {
	settings := s.store.GetSettings()
	user = s.currentUser(r)

	if user != nil {
		if user.MustChangePassword {
			return nil, nil, 0, "Password change required: please set a new password before running queries", http.StatusForbidden
		}
		return user, user.AllowedViews, user.RateLimitPerMinute, "", http.StatusOK
	}

	if settings.AccessMode == models.AccessModePublic {
		return nil, settings.PublicAllowedViews, settings.RateLimitPerMinute, "", http.StatusOK
	}

	return nil, nil, 0, "Authentication Required: Please sign in with your authorized account to query the Looking Glass", http.StatusUnauthorized
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) *models.UserAccount {
	u := s.currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "Administrator authentication required")
		return nil
	}
	if u.Role != "admin" {
		writeError(w, http.StatusForbidden, "Administrator role required")
		return nil
	}
	if u.MustChangePassword {
		writeError(w, http.StatusForbidden, "Password change required: please update the default password before accessing administrative controls")
		return nil
	}
	return u
}
