// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/models"
)

const maxIconDataURLLength = 400 * 1024 // ~290 KB binary image after base64 encoding

var (
	reSVGEventAttr          = regexp.MustCompile(`(?i)\bon[a-z0-9_]+\s*=`)
	allowedIconDataPrefixes = []string{
		"data:image/png;base64,",
		"data:image/jpeg;base64,",
		"data:image/jpg;base64,",
		"data:image/webp;base64,",
		"data:image/gif;base64,",
		"data:image/x-icon;base64,",
		"data:image/vnd.microsoft.icon;base64,",
		"data:image/svg+xml;base64,",
	}
)

func validateIconDataURL(fieldName, val string) error {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return nil
	}
	if len(trimmed) > maxIconDataURLLength {
		return fmt.Errorf("%s is too large (maximum image size is 256 KB)", fieldName)
	}
	lower := strings.ToLower(trimmed)
	matchedPrefix := ""
	for _, prefix := range allowedIconDataPrefixes {
		if strings.HasPrefix(lower, prefix) {
			matchedPrefix = prefix
			break
		}
	}
	if matchedPrefix == "" {
		return fmt.Errorf("%s must be a valid base64 image (PNG, ICO, SVG, WebP, JPG, or GIF)", fieldName)
	}
	b64Part := trimmed[len(matchedPrefix):]
	decoded, err := base64.StdEncoding.DecodeString(b64Part)
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("%s contains invalid base64 image data", fieldName)
	}
	if matchedPrefix == "data:image/svg+xml;base64," {
		svgStr := string(decoded)
		svgLower := strings.ToLower(svgStr)
		for _, bad := range []string{"<script", "javascript:", "data:text/html", "<foreignobject", "<iframe", "<embed", "<object", "xlink:href"} {
			if strings.Contains(svgLower, bad) {
				return fmt.Errorf("%s SVG contains disallowed active content (%s)", fieldName, bad)
			}
		}
		if reSVGEventAttr.MatchString(svgStr) {
			return fmt.Errorf("%s SVG contains disallowed inline event handler attributes", fieldName)
		}
	}
	return nil
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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max payload (allows 2 icons <= 256 KB each)
		var newSettings models.SystemSettings
		if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid settings payload")
			return
		}
		if newSettings.AccessMode != models.AccessModeAuthRequired && newSettings.AccessMode != models.AccessModePublic {
			writeError(w, http.StatusBadRequest, "Invalid access mode (allowed: auth_required or public)")
			return
		}
		newSettings.FaviconIcon = strings.TrimSpace(newSettings.FaviconIcon)
		newSettings.PortalLogo = strings.TrimSpace(newSettings.PortalLogo)
		if err := validateIconDataURL("favicon_icon", newSettings.FaviconIcon); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateIconDataURL("portal_logo", newSettings.PortalLogo); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if newSettings.MaxFilterRoutesV4 == 0 {
			newSettings.MaxFilterRoutesV4 = 50
		}
		if newSettings.MaxFilterRoutesV6 == 0 {
			newSettings.MaxFilterRoutesV6 = 50
		}
		if newSettings.MaxFilterRoutesV4 < 1 || newSettings.MaxFilterRoutesV4 > 5000 {
			writeError(w, http.StatusBadRequest, "max_filter_routes_ipv4 must be between 1 and 5000")
			return
		}
		if newSettings.MaxFilterRoutesV6 < 1 || newSettings.MaxFilterRoutesV6 > 5000 {
			writeError(w, http.StatusBadRequest, "max_filter_routes_ipv6 must be between 1 and 5000")
			return
		}
		prevSettings := s.store.GetAdminSettings()
		updated, err := s.store.UpdateSettings(newSettings)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if prevSettings.MaxFilterRoutesV4 != updated.MaxFilterRoutesV4 || prevSettings.MaxFilterRoutesV6 != updated.MaxFilterRoutesV6 {
			s.cache.Clear()
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
		bgp.InvalidateVRFRDCache()
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPSERT_VIEW (" + view.Name + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetRouteViews())
	case http.MethodDelete:
		id := models.RouteViewID(r.URL.Query().Get("id"))
		if err := s.store.DeleteRouteView(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cache.Clear()
		bgp.InvalidateVRFRDCache()
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
			writeError(w, http.StatusBadRequest, "RR node endpoint (gRPC address, socket path, or lg-agent URL) cannot be empty")
			return
		}
		for _, old := range s.store.GetRRNodes() {
			if old.ID == strings.TrimSpace(node.ID) && old.Endpoint != strings.TrimSpace(node.Endpoint) {
				bgp.CloseGRPCConnection(old.Endpoint)
			}
		}
		if err := s.store.UpsertRRNode(node); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.cache.Clear()
		bgp.InvalidateVRFRDCache()
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   "UPSERT_RR_NODE (" + node.Name + ")",
		})
		writeJSON(w, http.StatusOK, s.store.GetRRNodes())
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		for _, old := range s.store.GetRRNodes() {
			if old.ID == id {
				bgp.CloseGRPCConnection(old.Endpoint)
			}
		}
		if err := s.store.DeleteRRNode(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cache.Clear()
		bgp.InvalidateVRFRDCache()
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
		if bgp.IsRemoteAgentEndpoint(endpoint) {
			if health, err := bgp.ProbeRemoteAgent(r.Context(), endpoint, target.AgentToken); err == nil {
				reachable = true
				msg = fmt.Sprintf("Remote BIRD 2 lg-agent reachable (%dms): %s", time.Since(start).Milliseconds(), health.Message)
			} else {
				msg = fmt.Sprintf("Remote BIRD 2 lg-agent probe failed: %v", err)
			}
		} else if _, err := exec.LookPath("birdc"); err != nil {
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
		if bgp.IsRemoteAgentEndpoint(endpoint) {
			if health, err := bgp.ProbeRemoteAgent(r.Context(), endpoint, target.AgentToken); err == nil {
				reachable = true
				msg = fmt.Sprintf("Remote FRR lg-agent reachable (%dms): %s", time.Since(start).Milliseconds(), health.Message)
			} else {
				msg = fmt.Sprintf("Remote FRR lg-agent probe failed: %v", err)
			}
		} else if _, err := exec.LookPath("vtysh"); err != nil {
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
	_ = s.store.UpdateRRNodeHealth(target.ID, reachable, time.Now().Format(time.RFC3339))

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

func (s *Server) handleAdminSecurityLocks(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.loginGuard.ListEntries())
	case http.MethodDelete, http.MethodPost:
		target := strings.TrimSpace(r.URL.Query().Get("key"))
		if target == "" && r.Method == http.MethodPost {
			var body struct {
				Key string `json:"key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			target = strings.TrimSpace(body.Key)
		}
		if target == "" {
			writeError(w, http.StatusBadRequest, "key parameter is required (e.g. 1.2.3.4, admin, or all)")
			return
		}
		removed := s.loginGuard.Unban(target)
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: admin.Username,
			ClientIP: s.clientIP(r),
			Action:   fmt.Sprintf("UNBAN_LOGIN (%s, removed=%d)", target, removed),
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"removed": removed,
			"locks":   s.loginGuard.ListEntries(),
		})
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
	bgp.InvalidateVRFRDCache()
	s.store.AppendAuditLog(models.AuditLogEntry{
		Username: admin.Username,
		ClientIP: s.clientIP(r),
		Action:   "CLEAR_ROUTE_CACHE",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "cache_cleared"})
}
