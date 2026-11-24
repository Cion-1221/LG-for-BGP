// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"path/filepath"
	"testing"

	"lg-for-bgp/internal/models"
)

func TestSQLiteStoreFullPersistenceAndPoPViewIDs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "lg.db")

	st, err := NewAppStore("sqlite:" + dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	if st.DBDriver() != "sqlite" {
		t.Fatalf("expected DBDriver=sqlite, got %q", st.DBDriver())
	}

	st.SetDBPoolOptions(DBPoolOptions{
		MaxOpenConns:           25,
		MaxIdleConns:           5,
		ConnMaxLifetimeMinutes: 30,
		ConnMaxIdleTimeMinutes: 5,
	})

	settings := st.GetAdminSettings()
	settings.OrganizationName = "VyOS Edge LG"
	settings.MaxFilterRoutesV4 = 120
	settings.MaxFilterRoutesV6 = 80
	settings.FaviconIcon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
	settings.PortalLogo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
	settings.PrimaryASN = 18913
	settings.DatacenterCode = "HKG4-LG-RR02"
	if _, err := st.UpdateSettings(settings); err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	if err := st.UpsertPOP(models.POPGroup{ID: "HKG4-LG-RR02", Name: "HKG", Description: "Hong Kong", SortOrder: 1}); err != nil {
		t.Fatalf("UpsertPOP HKG failed: %v", err)
	}
	if err := st.UpsertPOP(models.POPGroup{ID: "SIN-LG-RR02", Name: "SIN", Description: "Singapore", SortOrder: 2}); err != nil {
		t.Fatalf("UpsertPOP SIN failed: %v", err)
	}

	if err := st.UpsertRouteView(models.RouteViewMeta{
		Name:        "CN Optimized Routing",
		VRFName:     "VRF-CN-OPTIMIZE",
		Type:        "bird2",
		BirdTableV6: "VRF-CN-OPTIMIZE-IPV6",
		POP:         "HKG4-LG-RR02",
	}); err != nil {
		t.Fatalf("UpsertRouteView HKG failed: %v", err)
	}
	if err := st.UpsertRouteView(models.RouteViewMeta{
		Name:    "CN Optimized Routing",
		VRFName: "VRF-CN-OPTIMIZE",
		Type:    "gobgp",
		POP:     "SIN-LG-RR02",
	}); err != nil {
		t.Fatalf("UpsertRouteView SIN failed: %v", err)
	}

	views := st.GetRouteViews()
	if len(views) != 2 || views[0].ID == views[1].ID {
		t.Fatalf("expected 2 distinct PoP-scoped views, got %+v", views)
	}

	if err := st.UpsertRRNode(models.RRNodeConfig{
		ID:         "rr-hkg-01",
		Name:       "HKG4-LG-RR02",
		Location:   "HKG4-LG-RR02",
		EngineType: "gobgp",
		LoopbackIP: "10.0.0.1",
		Endpoint:   "127.0.0.1:50051",
		Role:       "primary",
		Enabled:    true,
		Healthy:    true,
	}); err != nil {
		t.Fatalf("UpsertRRNode failed: %v", err)
	}

	if _, err := st.SaveUser(models.UserAccount{
		Username:     "noc_vyos",
		DisplayName:  "NOC VyOS",
		Company:      "ASLINE",
		Role:         "noc",
		AllowedViews: []models.RouteViewID{views[0].ID},
		Enabled:      true,
	}, "StrongPass@2026"); err != nil {
		t.Fatalf("SaveUser failed: %v", err)
	}
	if _, _, err := st.Authenticate("noc_vyos", "StrongPass@2026"); err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Verify async audit queue flushes deterministically during Close()
	st.AppendAuditLog(models.AuditLogEntry{
		Username:   "noc_vyos",
		ClientIP:   "192.0.2.10",
		Action:     "BGP_QUERY",
		QueryType:  "prefix",
		Target:     "1.1.1.1",
		Views:      string(views[0].ID),
		RRNode:     "HKG4-LG-RR02",
		DurationMs: 12,
	})

	if err := st.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	st2, err := NewAppStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen sqlite store: %v", err)
	}
	defer func() { _ = st2.Close() }()

	reloadedViews := st2.GetRouteViews()
	if len(reloadedViews) != 2 || reloadedViews[0].BirdTableV6 != "VRF-CN-OPTIMIZE-IPV6" {
		t.Fatalf("expected BirdTableV6 to persist across SQLite reopen, got %+v", reloadedViews)
	}
	logs := st2.GetAuditLogs()
	if len(logs) != 1 || logs[0].Target != "1.1.1.1" || logs[0].Timestamp.IsZero() {
		t.Fatalf("async audit logs did not flush cleanly on Close(): %+v", logs)
	}

	if err := st2.DeletePOP("HKG4-LG-RR02"); err == nil {
		t.Fatalf("expected DeletePOP to fail while rr-hkg-01 is still bound to HKG4-LG-RR02")
	}
	if err := st2.DeleteRRNode("rr-hkg-01"); err != nil {
		t.Fatalf("DeleteRRNode failed: %v", err)
	}
	if err := st2.DeletePOP("HKG4-LG-RR02"); err != nil {
		t.Fatalf("expected DeletePOP to succeed after removing bound RR, got %v", err)
	}
}
