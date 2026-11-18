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

	// Setup test VRF views, test RR node, and test customer account
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
	srv := NewServer(st, eng, cache, "")
	handler := srv.Handler()

	// 1. Default mode is public so users opening LG directly can query right away
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

	// 2. Login as customer tenant_alpha (only allowed lsys_opt and vrf_dia)
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

	// 3. Customer attempts to query unauthorized view vrf_transit_a -> must return 403 Forbidden
	reqForbidden := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"8.8.8.8","views":["vrf_transit_a"]}`))
	reqForbidden.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recForbidden := httptest.NewRecorder()
	handler.ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when customer queries unauthorized table, got %d", recForbidden.Code)
	}

	// 4. Customer queries allowed views (lsys_opt + vrf_dia) -> must return 200 OK
	reqAllowed := httptest.NewRequest(http.MethodPost, "/api/v1/bgp/lookup", bytes.NewBufferString(`{"query_type":"prefix","target":"202.96.209.133","views":["lsys_opt","vrf_dia"]}`))
	reqAllowed.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recAllowed := httptest.NewRecorder()
	handler.ServeHTTP(recAllowed, reqAllowed)
	if recAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for allowed views, got %d: %s", recAllowed.Code, recAllowed.Body.String())
	}

	var lookupResp models.LookupResponse
	if err := json.Unmarshal(recAllowed.Body.Bytes(), &lookupResp); err != nil {
		t.Fatalf("failed to unmarshal lookup response: %v", err)
	}
	if len(lookupResp.Results) != 2 {
		t.Fatalf("expected 2 view results, got %d", len(lookupResp.Results))
	}
}
