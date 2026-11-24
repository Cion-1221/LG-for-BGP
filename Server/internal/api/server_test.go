// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

func TestEndToEndAPIAndMultiViewLookup(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.NewAppStore(filepath.Join(tmpDir, "state.json"))
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}

	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:                "lsys_opt",
		Name:              "Optimized Routing",
		VRFName:           "LSYS-OPT",
		Type:              "gobgp",
		JuniperSourceIPv4: "10.255.0.1",
	})
	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:                "vrf_dia",
		Name:              "Global DIA",
		VRFName:           "VRF-DIA",
		Type:              "gobgp",
		JuniperSourceIPv4: "10.255.0.10",
	})
	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:                "vrf_transit_a",
		Name:              "Transit A",
		VRFName:           "VRF-TRANSIT-A",
		Type:              "gobgp",
		JuniperSourceIPv4: "10.255.0.20",
	})
	_ = st.UpsertRRNode(models.RRNodeConfig{
		ID:         "rr-01",
		Name:       "RR-01 (Primary Collector)",
		EngineType: "gobgp",
		LoopbackIP: "10.255.255.101",
		Endpoint:   "127.0.0.1:50051",
		Role:       "primary",
		Enabled:    true,
	})
	_, _ = st.SaveUser(models.UserAccount{
		Username:     "tenant_alpha",
		DisplayName:  "Tenant Alpha",
		Role:         "customer",
		AllowedViews: []models.RouteViewID{"lsys_opt", "vrf_dia"},
		Enabled:      true,
	}, "TenantA@123")

	cache := security.NewTTLCache()
	eng := bgp.NewEngine(st, cache)
	srv := NewServer(st, eng, cache, "", "127.0.0.1", "::1", "10.100.0.0/16")
	handler := srv.Handler()

	// 1. Verify X-Forwarded-For right-to-left spoofing defense!
	reqSpoof := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	reqSpoof.RemoteAddr = "127.0.0.1:44444"
	reqSpoof.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.77, 10.100.1.5")
	if gotIP := srv.clientIP(reqSpoof); gotIP != "198.51.100.77" {
		t.Fatalf("XFF spoofing defense failed: expected rightmost untrusted IP 198.51.100.77, got %q", gotIP)
	}
	reqUntrustedPeer := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	reqUntrustedPeer.RemoteAddr = "198.51.100.88:55555"
	reqUntrustedPeer.Header.Set("X-Forwarded-For", "1.2.3.4")
	if gotIP := srv.clientIP(reqUntrustedPeer); gotIP != "198.51.100.88" {
		t.Fatalf("expected untrusted peer XFF header to be ignored, got %q", gotIP)
	}

	// 2. Default mode is public so users opening LG directly can query right away
	reqPublic := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"8.8.8.8","views":["lsys_opt"]}`))
	recPublic := httptest.NewRecorder()
	handler.ServeHTTP(recPublic, reqPublic)
	if recPublic.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for direct public LG lookup, got %d: %s", recPublic.Code, recPublic.Body.String())
	}

	// Switch to auth_required mode and verify unauthenticated lookup returns 401
	settings := st.GetSettings()
	settings.AccessMode = models.AccessModeAuthRequired
	_, _ = st.UpdateSettings(settings)

	reqUnauth := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"8.8.8.8","views":["lsys_opt"]}`))
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated lookup in auth_required mode, got %d", recUnauth.Code)
	}

	// 3. Login as customer tenant_alpha (only allowed lsys_opt and vrf_dia)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"tenant_alpha","password":"TenantA@123"}`))
	recLogin := httptest.NewRecorder()
	handler.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", recLogin.Code, recLogin.Body.String())
	}
	var loginResp struct {
		Token string             `json:"token"`
		User  models.UserAccount `json:"user"`
	}
	_ = json.Unmarshal(recLogin.Body.Bytes(), &loginResp)

	// 4. Customer attempts to query unauthorized view vrf_transit_a -> must return 403 Forbidden
	reqForbidden := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"8.8.8.8","views":["vrf_transit_a"]}`))
	reqForbidden.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recForbidden := httptest.NewRecorder()
	handler.ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when customer queries unauthorized table, got %d", recForbidden.Code)
	}

	// 5. Customer queries allowed views (lsys_opt + vrf_dia) -> must return 200 OK
	reqAllowed := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"202.96.209.133","views":["lsys_opt","vrf_dia"]}`))
	reqAllowed.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recAllowed := httptest.NewRecorder()
	handler.ServeHTTP(recAllowed, reqAllowed)
	if recAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for allowed views, got %d: %s", recAllowed.Code, recAllowed.Body.String())
	}

	// 6. Verify cross-PoP view query is rejected with HTTP 400
	_ = st.UpsertRouteView(models.RouteViewMeta{
		ID:      "hkg_only_vrf",
		Name:    "HKG Only",
		VRFName: "VRF-HKG-ONLY",
		Type:    "gobgp",
		POP:     "HKG-POP",
	})
	settings = st.GetSettings()
	settings.AccessMode = models.AccessModePublic
	_, _ = st.UpdateSettings(settings)

	reqCrossPoP := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"8.8.8.8","views":["hkg_only_vrf"],"pop":"SIN-POP"}`))
	recCrossPoP := httptest.NewRecorder()
	handler.ServeHTTP(recCrossPoP, reqCrossPoP)
	if recCrossPoP.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for cross-PoP VRF query, got %d: %s", recCrossPoP.Code, recCrossPoP.Body.String())
	}

	// 7. Verify login brute-force lockout (5 bad attempts -> 429) and Admin manual unban
	for i := 1; i <= 5; i++ {
		reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"tenant_alpha","password":"WrongPassword"}`))
		reqBad.RemoteAddr = "198.51.100.22:54321"
		recBad := httptest.NewRecorder()
		handler.ServeHTTP(recBad, reqBad)
		if i < 5 && recBad.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, recBad.Code)
		}
		if i == 5 && recBad.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt 5: expected 429 lock, got %d: %s", recBad.Code, recBad.Body.String())
		}
	}

	// Login as default admin (which starts with MustChangePassword=true)
	reqAdminLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"Admin@123456"}`))
	reqAdminLogin.RemoteAddr = "203.0.113.10:12345"
	recAdminLogin := httptest.NewRecorder()
	handler.ServeHTTP(recAdminLogin, reqAdminLogin)
	if recAdminLogin.Code != http.StatusOK {
		t.Fatalf("admin login failed: %d %s", recAdminLogin.Code, recAdminLogin.Body.String())
	}
	var adminResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(recAdminLogin.Body.Bytes(), &adminResp)

	// 8. Verify backend enforces MustChangePassword (blocks /api/v1/admin/* with 403 BEFORE password change!)
	reqBeforePwdChange := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/security/locks?key=all", nil)
	reqBeforePwdChange.Header.Set("Authorization", "Bearer "+adminResp.Token)
	recBeforePwdChange := httptest.NewRecorder()
	handler.ServeHTTP(recBeforePwdChange, reqBeforePwdChange)
	if recBeforePwdChange.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when MustChangePassword=true on admin API, got %d", recBeforePwdChange.Code)
	}

	// Change admin password (also testing leading/trailing space preservation!)
	reqChgPwd := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewBufferString(`{"current_password":"Admin@123456","new_password":"  NewAdmin@2026!  "}`))
	reqChgPwd.Header.Set("Authorization", "Bearer "+adminResp.Token)
	recChgPwd := httptest.NewRecorder()
	handler.ServeHTTP(recChgPwd, reqChgPwd)
	if recChgPwd.Code != http.StatusOK {
		t.Fatalf("admin change-password failed: %d %s", recChgPwd.Code, recChgPwd.Body.String())
	}
	_ = json.Unmarshal(recChgPwd.Body.Bytes(), &adminResp)

	// Verify exact whitespace preservation on subsequent login
	reqSpaceLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"  NewAdmin@2026!  "}`))
	reqSpaceLogin.RemoteAddr = "203.0.113.10:12345"
	recSpaceLogin := httptest.NewRecorder()
	handler.ServeHTTP(recSpaceLogin, reqSpaceLogin)
	if recSpaceLogin.Code != http.StatusOK {
		t.Fatalf("expected password with spaces to authenticate identically after change-password, got %d", recSpaceLogin.Code)
	}

	// Unban via Admin Security endpoint now succeeds with 200 OK
	reqUnban := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/security/locks?key=all", nil)
	reqUnban.Header.Set("Authorization", "Bearer "+adminResp.Token)
	recUnban := httptest.NewRecorder()
	handler.ServeHTTP(recUnban, reqUnban)
	if recUnban.Code != http.StatusOK {
		t.Fatalf("expected 200 on manual unban, got %d: %s", recUnban.Code, recUnban.Body.String())
	}

	reqUnblocked := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"tenant_alpha","password":"TenantA@123"}`))
	reqUnblocked.RemoteAddr = "198.51.100.22:54321"
	recUnblocked := httptest.NewRecorder()
	handler.ServeHTTP(recUnblocked, reqUnblocked)
	if recUnblocked.Code != http.StatusOK {
		t.Fatalf("expected 200 after manual unban, got %d: %s", recUnblocked.Code, recUnblocked.Body.String())
	}

	// 9. Verify custom favicon_icon & portal_logo upload validation and malicious SVG event rejection
	validPNG := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
	goodSettings := st.GetAdminSettings()
	goodSettings.OrganizationName = "ASLINE LG Portal"
	goodSettings.MaxFilterRoutesV4 = 150
	goodSettings.MaxFilterRoutesV6 = 90
	goodSettings.FaviconIcon = validPNG
	goodSettings.PortalLogo = validPNG
	goodPayload, _ := json.Marshal(goodSettings)
	reqSetGood := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewReader(goodPayload))
	reqSetGood.Header.Set("Authorization", "Bearer "+adminResp.Token)
	recSetGood := httptest.NewRecorder()
	handler.ServeHTTP(recSetGood, reqSetGood)
	if recSetGood.Code != http.StatusOK {
		t.Fatalf("expected 200 saving valid PNG icons, got %d: %s", recSetGood.Code, recSetGood.Body.String())
	}

	badSettings := goodSettings
	badSettings.FaviconIcon = "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIj48L3N2Zz4="
	badPayload, _ := json.Marshal(badSettings)
	reqSetBad := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewReader(badPayload))
	reqSetBad.Header.Set("Authorization", "Bearer "+adminResp.Token)
	recSetBad := httptest.NewRecorder()
	handler.ServeHTTP(recSetBad, reqSetBad)
	if recSetBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting malicious SVG icon, got %d: %s", recSetBad.Code, recSetBad.Body.String())
	}

	// 10. Public Portal bootstrap, lookup, and summary MUST NEVER leak RR/Agent IPs or endpoints
	reqBootPub := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap", nil)
	recBootPub := httptest.NewRecorder()
	handler.ServeHTTP(recBootPub, reqBootPub)
	bootPubBody := recBootPub.Body.String()
	if bytes.Contains([]byte(bootPubBody), []byte("10.255.255.101")) || bytes.Contains([]byte(bootPubBody), []byte("127.0.0.1:50051")) {
		t.Fatalf("public bootstrap leaked RR loopback IP or endpoint: %s", bootPubBody)
	}

	srv.Close()
	cache.Close()
	_ = st.Close()
}
