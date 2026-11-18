package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

type Server struct {
	store          *store.AppStore
	engine         *bgp.Engine
	cache          *security.TTLCache
	rateLimiter    *security.RateLimiter
	staticDir      string
	accessLog      bool
	trustedProxies map[string]bool
}

func NewServer(st *store.AppStore, eng *bgp.Engine, cache *security.TTLCache, staticDir string, trustedProxies ...string) *Server {
	tp := make(map[string]bool)
	if len(trustedProxies) == 0 {
		tp["127.0.0.1"] = true
		tp["::1"] = true
	} else {
		for _, p := range trustedProxies {
			tp[strings.TrimSpace(p)] = true
		}
	}
	return &Server{
		store:          st,
		engine:         eng,
		cache:          cache,
		rateLimiter:    security.NewRateLimiter(),
		staticDir:      staticDir,
		accessLog:      true,
		trustedProxies: tp,
	}
}

func (s *Server) SetAccessLog(enabled bool) {
	s.accessLog = enabled
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
	mux.HandleFunc("/api/v1/communities", s.handleCommunities)

	mux.HandleFunc("/api/v1/admin/settings", s.handleAdminSettings)
	mux.HandleFunc("/api/v1/admin/views", s.handleAdminViews)
	mux.HandleFunc("/api/v1/admin/pops", s.handleAdminPOPs)
	mux.HandleFunc("/api/v1/admin/rr-nodes", s.handleAdminRRNodes)
	mux.HandleFunc("/api/v1/admin/rr-nodes/probe", s.handleAdminProbeRRNode)
	mux.HandleFunc("/api/v1/admin/users", s.handleAdminUsers)
	mux.HandleFunc("/api/v1/admin/communities", s.handleAdminCommunities)
	mux.HandleFunc("/api/v1/admin/audit-logs", s.handleAdminAuditLogs)
	mux.HandleFunc("/api/v1/admin/cache/clear", s.handleAdminClearCache)

	mux.HandleFunc("/", s.handleStaticUI)

	return s.corsMiddleware(mux)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
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

func (s *Server) clientIP(r *http.Request) string {
	remoteHost := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteHost = h
	}
	if len(s.trustedProxies) == 0 || s.trustedProxies[remoteHost] {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	return remoteHost
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
		return user, user.AllowedViews, user.RateLimitPerMinute, "", http.StatusOK
	}

	if settings.AccessMode == models.AccessModePublic {
		return nil, settings.PublicAllowedViews, settings.RateLimitPerMinute, "", http.StatusOK
	}

	return nil, nil, 0, "Authentication Required: Please sign in with your authorized account to query the Looking Glass", http.StatusUnauthorized
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	settings := s.store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"service": "lg-for-bgp-server",
		"asn":     settings.PrimaryASN,
		"dc":      settings.DatacenterCode,
	})
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	hadAuthHeader := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) != ""
	user := s.currentUser(r)
	sessionInvalidated := hadAuthHeader && user == nil

	var settings models.SystemSettings
	if user != nil && user.Role == "admin" {
		settings = s.store.GetAdminSettings()
	} else {
		settings = s.store.GetPublicSettings()
	}

	entrySlug := r.URL.Query().Get("entry")
	adminEntryVerified := s.store.VerifyAdminSlug(entrySlug) || (user != nil && user.Role == "admin" && entrySlug != "" && entrySlug != "/")

	allViews := s.store.GetRouteViews()

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
		"rr_nodes":             s.store.GetRRNodes(),
		"communities":          s.store.GetCommunities(),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, token, err := s.store.Authenticate(strings.TrimSpace(body.Username), body.Password)
	if err != nil {
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: body.Username,
			ClientIP: s.clientIP(r),
			Action:   "LOGIN_FAILED",
		})
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	s.store.AppendAuditLog(models.AuditLogEntry{
		Username: user.Username,
		ClientIP: s.clientIP(r),
		Action:   "LOGIN_SUCCESS",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated or session expired")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	u := s.currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to change password")
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	updatedUser, newToken, err := s.store.ChangePassword(u.Username, body.CurrentPassword, body.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.store.AppendAuditLog(models.AuditLogEntry{
		Username: u.Username,
		ClientIP: s.clientIP(r),
		Action:   "CHANGE_PASSWORD",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": newToken,
		"user":  updatedUser,
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

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBGPSummary(w http.ResponseWriter, r *http.Request) {
	_, allowedViews, _, errMsg, status := s.resolveAccess(r)
	if status != http.StatusOK {
		writeError(w, status, errMsg)
		return
	}

	allowedSet := make(map[models.RouteViewID]bool)
	for _, v := range allowedViews {
		allowedSet[v] = true
	}

	allNeighbors := s.engine.GetNeighborSummary()
	var filtered []models.BGPNeighborSummary
	for _, n := range allNeighbors {
		if allowedSet[n.ViewID] {
			filtered = append(filtered, n)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rr_nodes":  s.store.GetRRNodes(),
		"neighbors": filtered,
		"timestamp": time.Now(),
	})
}

func (s *Server) handleCommunities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.GetCommunities())
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
	return u
}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}

	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.store.GetAdminSettings())
		return
	}

	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		var newSettings models.SystemSettings
		if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid settings payload")
			return
		}
		if newSettings.AccessMode != models.AccessModeAuthRequired && newSettings.AccessMode != models.AccessModePublic {
			writeError(w, http.StatusBadRequest, "Invalid access mode (allowed: auth_required or public)")
			return
		}
		updated, err := s.store.UpdateSettings(newSettings)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPDATE_SETTINGS (mode=" + string(updated.AccessMode) + ")",
		})
		writeJSON(w, http.StatusOK, updated)
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

func (s *Server) handleAdminViews(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.GetRouteViews())
	case http.MethodPost, http.MethodPut:
		var view models.RouteViewMeta
		if err := json.NewDecoder(r.Body).Decode(&view); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid VRF route view payload")
			return
		}
		if strings.TrimSpace(view.Name) == "" {
			writeError(w, http.StatusBadRequest, "Display Name (name) cannot be empty")
			return
		}
		if err := s.store.UpsertRouteView(view); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.cache.Clear()
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPSERT_VIEW (" + string(view.ID) + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetRouteViews())
	case http.MethodDelete:
		id := models.RouteViewID(r.URL.Query().Get("id"))
		if err := s.store.DeleteRouteView(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cache.Clear()
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "DELETE_VIEW (" + string(id) + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetRouteViews())
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminPOPs(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.GetPOPs())
	case http.MethodPost, http.MethodPut:
		var pop models.POPGroup
		if err := json.NewDecoder(r.Body).Decode(&pop); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid PoP group payload")
			return
		}
		if err := s.store.UpsertPOP(pop); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPSERT_POP (" + pop.ID + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetPOPs())
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeletePOP(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "DELETE_POP (" + id + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetPOPs())
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminRRNodes(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.GetRRNodes())
	case http.MethodPost, http.MethodPut:
		var node models.RRNodeConfig
		if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid RR node configuration payload")
			return
		}
		if strings.TrimSpace(node.Name) == "" {
			writeError(w, http.StatusBadRequest, "RR node display name (name) cannot be empty")
			return
		}
		if strings.TrimSpace(node.Endpoint) == "" {
			writeError(w, http.StatusBadRequest, "RR node endpoint (gRPC address or control socket path) cannot be empty")
			return
		}
		if err := s.store.UpsertRRNode(node); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.cache.Clear()
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPSERT_RR_NODE (" + node.Name + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetRRNodes())
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteRRNode(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cache.Clear()
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "DELETE_RR_NODE (" + id + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetRRNodes())
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminProbeRRNode(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	targetID := strings.TrimSpace(req.ID)
	if targetID == "" {
		targetID = strings.TrimSpace(r.URL.Query().Get("id"))
	}

	nodes := s.store.GetRRNodes()
	var target *models.RRNodeConfig
	for i := range nodes {
		if nodes[i].ID == targetID {
			target = &nodes[i]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "RR node not found")
		return
	}

	start := time.Now()
	reachable := false
	msg := ""
	eng := strings.ToLower(strings.TrimSpace(target.EngineType))
	endpoint := strings.TrimSpace(target.Endpoint)

	switch eng {
	case "gobgp":
		conn, err := net.DialTimeout("tcp", endpoint, 1500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			reachable = true
			msg = fmt.Sprintf("GoBGP gRPC endpoint %s is reachable (%dms)", endpoint, time.Since(start).Milliseconds())
		} else {
			msg = fmt.Sprintf("GoBGP gRPC endpoint %s connection failed: %v", endpoint, err)
		}
	case "bird2":
		if _, err := exec.LookPath("birdc"); err != nil {
			msg = fmt.Sprintf("BIRD 2 client (birdc) not found in PATH (%v)", err)
		} else if endpoint != "" && !strings.EqualFold(endpoint, "local") {
			if _, errStat := os.Stat(endpoint); errStat == nil {
				reachable = true
				msg = fmt.Sprintf("BIRD 2 control socket %s is available", endpoint)
			} else {
				msg = fmt.Sprintf("BIRD 2 control socket %s not found: %v", endpoint, errStat)
			}
		} else {
			reachable = true
			msg = "BIRD 2 client (birdc) is installed and ready"
		}
	case "frr":
		if _, err := exec.LookPath("vtysh"); err != nil {
			msg = fmt.Sprintf("FRR client (vtysh) not found in PATH (%v)", err)
		} else if endpoint != "" && !strings.EqualFold(endpoint, "local") {
			if _, errStat := os.Stat(endpoint); errStat == nil {
				reachable = true
				msg = fmt.Sprintf("FRR vtysh socket directory %s is available", endpoint)
			} else {
				msg = fmt.Sprintf("FRR vtysh socket directory %s not found: %v", endpoint, errStat)
			}
		} else {
			reachable = true
			msg = "FRR client (vtysh) is installed and ready"
		}
	default:
		msg = fmt.Sprintf("Unknown RR engine type: %s", eng)
	}

	latencyMs := time.Since(start).Milliseconds()
	target.Healthy = reachable
	target.LastChecked = time.Now().Format(time.RFC3339)
	_ = s.store.UpsertRRNode(*target)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         target.ID,
		"reachable":  reachable,
		"latency_ms": latencyMs,
		"message":    msg,
		"rr_nodes":   s.store.GetRRNodes(),
	})
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.GetUsers())
	case http.MethodPost, http.MethodPut:
		var payload struct {
			models.UserAccount
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid user account payload")
			return
		}
		saved, err := s.store.SaveUser(payload.UserAccount, payload.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPSERT_USER (" + saved.Username + ")",
		})
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteUser(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "DELETE_USER (" + id + ")",
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminCommunities(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}

	switch r.Method {
	case http.MethodPost, http.MethodPut:
		var entry models.CommunityDictEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid community dictionary entry")
			return
		}
		if _, err := security.ValidateCommunity(entry.Community); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.store.UpsertCommunity(entry); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.store.GetCommunities())
	case http.MethodDelete:
		comm := r.URL.Query().Get("community")
		if err := s.store.DeleteCommunity(comm); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.store.GetCommunities())
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminAuditLogs(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.store.GetAuditLogs())
}

func (s *Server) handleAdminClearCache(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}
	s.cache.Clear()
	s.store.AppendAuditLog(models.AuditLogEntry{
		Username: admin.Username,
		ClientIP: s.clientIP(r),
		Action:   "CLEAR_ROUTE_CACHE",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "cache_cleared"})
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
