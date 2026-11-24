// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	settings := s.store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"service":   "lg-for-bgp-server",
		"version":   "v2.0.0",
		"db_driver": s.store.DBDriver(),
		"asn":       settings.PrimaryASN,
		"dc":        settings.DatacenterCode,
	})
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	hadAuthHeader := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) != ""
	user := s.currentUser(r)
	sessionInvalidated := hadAuthHeader && user == nil
	// Only expose internal admin configuration once the administrator has completed any mandatory password change
	isAdminFull := user != nil && user.Role == "admin" && !user.MustChangePassword
	isAdminRole := user != nil && user.Role == "admin"

	var settings models.SystemSettings
	var rrNodes []models.RRNodeConfig
	if isAdminFull {
		settings = s.store.GetAdminSettings()
		rrNodes = s.store.GetRRNodes()
	} else {
		settings = s.store.GetPublicSettings()
		rrNodes = s.store.GetPublicRRNodes()
	}

	entrySlug := r.URL.Query().Get("entry")
	adminEntryVerified := s.store.VerifyAdminSlug(entrySlug) || (isAdminRole && entrySlug != "" && entrySlug != "/")

	allViews := s.store.GetRouteViews()
	if !isAdminFull {
		for i := range allViews {
			allViews[i].JuniperSourceIPv4 = ""
			allViews[i].JuniperSourceIPv6 = ""
		}
	}

	var allowedIDs []models.RouteViewID
	if user != nil {
		allowedIDs = user.AllowedViews
	} else if settings.AccessMode == models.AccessModePublic {
		allowedIDs = settings.PublicAllowedViews
	}

	allowedSet := make(map[models.RouteViewID]bool)
	for _, id := range allowedIDs {
		allowedSet[id] = true
	}

	var permittedViews []models.RouteViewMeta
	for _, v := range allViews {
		if allowedSet[v.ID] {
			permittedViews = append(permittedViews, v)
		}
	}
	if permittedViews == nil {
		permittedViews = []models.RouteViewMeta{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"settings":             settings,
		"current_user":         user,
		"session_invalidated":  sessionInvalidated,
		"admin_entry_verified": adminEntryVerified,
		"permitted_views":      permittedViews,
		"all_views":            allViews,
		"pops":                 s.store.GetPOPs(),
		"rr_nodes":             rrNodes,
	})
}

func (s *Server) handleBGPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	user, allowedViews, rateLimit, errMsg, status := s.resolveAccess(r)
	if status != http.StatusOK {
		writeError(w, status, errMsg)
		return
	}

	rateKey := s.clientIP(r)
	username := "public-anonymous"
	if user != nil {
		rateKey = "user:" + user.Username
		username = user.Username
	}
	if !s.rateLimiter.Allow(rateKey, rateLimit) {
		writeError(w, http.StatusTooManyRequests, "Rate limit exceeded for current account/IP; please try again shortly")
		return
	}

	var req models.LookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	req.QueryType = strings.ToLower(strings.TrimSpace(req.QueryType))
	if req.QueryType == "" {
		req.QueryType = "prefix"
	}

	switch req.QueryType {
	case "prefix":
		norm, _, _, err := security.ValidatePrefixOrIP(req.Target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Target = norm
	case "aspath":
		cleaned, err := security.ValidateASPathOrASN(req.Target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Target = cleaned
	case "community":
		cleaned, err := security.ValidateCommunity(req.Target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Target = cleaned
	default:
		writeError(w, http.StatusBadRequest, "Unsupported query type (allowed: prefix, aspath, community)")
		return
	}

	knownViews := s.store.GetRouteViewMap()
	validatedViews, err := security.ValidateRouteViews(req.Views, allowedViews, knownViews)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	req.POP = strings.TrimSpace(req.POP)
	if req.POP != "" && !strings.EqualFold(req.POP, "all") && !strings.EqualFold(req.POP, "auto") {
		allRRs := s.store.GetRRNodes()
		for _, vid := range validatedViews {
			vm := knownViews[vid]
			if !bgp.ViewBelongsToPOP(vm, req.POP, allRRs) {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("route view [%s] is not bound to any active RR node in PoP %q", vid, req.POP))
				return
			}
		}
	}
	req.Views = validatedViews

	start := time.Now()
	resp, err := s.engine.ExecuteLookup(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var viewStrs []string
	for _, v := range req.Views {
		viewStrs = append(viewStrs, string(v))
	}
	s.store.AppendAuditLog(models.AuditLogEntry{
		Username:   username,
		ClientIP:   s.clientIP(r),
		Action:     "BGP_QUERY",
		QueryType:  req.QueryType,
		Target:     req.Target,
		Views:      strings.Join(viewStrs, ","),
		RRNode:     resp.RRNodeUsed,
		DurationMs: time.Since(start).Milliseconds(),
	})

	if user == nil || user.Role != "admin" {
		for i := range resp.Results {
			resp.Results[i].View.JuniperSourceIPv4 = ""
			resp.Results[i].View.JuniperSourceIPv6 = ""
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBGPSummary(w http.ResponseWriter, r *http.Request) {
	if admin := s.requireAdmin(w, r); admin == nil {
		return
	}

	allNeighbors := s.engine.GetNeighborSummary()
	if allNeighbors == nil {
		allNeighbors = []models.BGPNeighborSummary{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rr_nodes":  s.store.GetRRNodes(),
		"neighbors": allNeighbors,
		"timestamp": time.Now(),
	})
}

func (s *Server) handleStaticUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, http.StatusNotFound, "API endpoint not found")
		return
	}
	if s.staticDir == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"service": "LG-for-BGP Multi-Instance Looking Glass API Server",
			"status":  "running",
			"docs":    "Point UI VITE_API_BASE_URL to this server or set -ui-dir to serve the built UI directly.",
		})
		return
	}

	cleanPath := filepath.Clean(r.URL.Path)
	if cleanPath == "." || cleanPath == "/" || cleanPath == `\` {
		http.ServeFile(w, r, filepath.Join(s.staticDir, "index.html"))
		return
	}
	targetFile := filepath.Join(s.staticDir, cleanPath)
	if info, err := os.Stat(targetFile); err == nil && !info.IsDir() {
		http.ServeFile(w, r, targetFile)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.staticDir, "index.html"))
}
