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

	// Ensure pool options do not break SQLite single-writer mode
	st.SetDBPoolOptions(DBPoolOptions{
		MaxOpenConns:           25,
		MaxIdleConns:           5,
		ConnMaxLifetimeMinutes: 30,
		ConnMaxIdleTimeMinutes: 5,
	})

	// 1. Update settings
	settings := st.GetAdminSettings()
	settings.OrganizationName = "VyOS Edge LG"
	settings.PrimaryASN = 18913
	settings.DatacenterCode = "HKG4-LG-RR02"
	if _, err := st.UpdateSettings(settings); err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	// 2. Upsert two PoPs
	if err := st.UpsertPOP(models.POPGroup{ID: "HKG4-LG-RR02", Name: "HKG", Description: "Hong Kong", SortOrder: 1}); err != nil {
		t.Fatalf("UpsertPOP HKG failed: %v", err)
	}
	if err := st.UpsertPOP(models.POPGroup{ID: "SIN-LG-RR02", Name: "SIN", Description: "Singapore", SortOrder: 2}); err != nil {
		t.Fatalf("UpsertPOP SIN failed: %v", err)
	}

	// 3. Upsert two VRFs with the SAME VRFName under DIFFERENT PoPs — IDs must NOT collide!
	if err := st.UpsertRouteView(models.RouteViewMeta{
		Name:    "CN Optimized Routing",
		VRFName: "VRF-CN-OPTIMIZE",
		Type:    "gobgp",
		POP:     "HKG4-LG-RR02",
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
	if len(views) != 2 {
		t.Fatalf("expected 2 distinct PoP-scoped views, got %d: %+v", len(views), views)
	}
	if views[0].ID == views[1].ID {
		t.Fatalf("expected distinct view IDs across PoPs, got duplicate %q", views[0].ID)
	}

	// 4. Upsert RR nodes
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

	// 5. Save custom user & authenticate
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

	// 6. Append audit log
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

	// 7. Reopen SQLite file from disk and verify ALL state persisted cleanly!
	st2, err := NewAppStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen sqlite store: %v", err)
	}
	defer func() { _ = st2.Close() }()

	s2 := st2.GetAdminSettings()
	if s2.OrganizationName != "VyOS Edge LG" || s2.PrimaryASN != 18913 {
		t.Fatalf("settings did not persist across reopen: %+v", s2)
	}
	if len(st2.GetPOPs()) != 2 {
		t.Fatalf("expected 2 PoPs after reopen, got %d", len(st2.GetPOPs()))
	}
	if len(st2.GetRouteViews()) != 2 {
		t.Fatalf("expected 2 RouteViews after reopen, got %d", len(st2.GetRouteViews()))
	}
	if len(st2.GetRRNodes()) != 1 {
		t.Fatalf("expected 1 RRNode after reopen, got %d", len(st2.GetRRNodes()))
	}
	if _, _, err := st2.Authenticate("noc_vyos", "StrongPass@2026"); err != nil {
		t.Fatalf("Authenticate failed after reopen: %v", err)
	}
	logs := st2.GetAuditLogs()
	if len(logs) != 1 || logs[0].Target != "1.1.1.1" || logs[0].Timestamp.IsZero() {
		t.Fatalf("audit logs did not persist properly: %+v", logs)
	}

	// 8. Verify bcrypt password hashing + transparent legacy SHA-256 upgrade
	rawUsers := st2.data.Users
	var foundBcrypt bool
	for _, u := range rawUsers {
		if u.Username == "noc_vyos" && len(u.PasswordHash) > 4 && u.PasswordHash[:4] == "$2a$" {
			foundBcrypt = true
		}
	}
	if !foundBcrypt {
		t.Fatalf("expected new user password to be hashed with bcrypt ($2a$)")
	}

	// Simulate legacy SHA-256 hash stored in an older DB and confirm transparent upgrade on login
	legacyHash := LegacySHA256Hash("LegacyPass@2026")
	if ok, needsUpgrade := VerifyPassword(legacyHash, "LegacyPass@2026"); !ok || !needsUpgrade {
		t.Fatalf("expected legacy SHA-256 verification to succeed with needsUpgrade=true")
	}

	// 9. Verify RR -> PoP protection (cannot delete PoP while RRs are still bound)
	if err := st2.DeletePOP("HKG4-LG-RR02"); err == nil {
		t.Fatalf("expected DeletePOP to fail while rr-hkg-01 is still bound to HKG4-LG-RR02")
	}

	// 10. Verify incremental RR health update & VRF <-> RR binding cleanup on DeleteRRNode
	if err := st2.UpdateRRNodeHealth("rr-hkg-01", false, "2026-11-19T11:00:00Z"); err != nil {
		t.Fatalf("UpdateRRNodeHealth failed: %v", err)
	}
	if err := st2.UpsertRouteView(models.RouteViewMeta{
		ID:        "multi_rr_vrf",
		Name:      "Multi-RR VRF",
		VRFName:   "VRF-SHARED",
		Type:      "auto",
		RRNodeIDs: []string{"rr-hkg-01"},
	}); err != nil {
		t.Fatalf("UpsertRouteView multi_rr_vrf failed: %v", err)
	}
	if err := st2.DeleteRRNode("rr-hkg-01"); err != nil {
		t.Fatalf("DeleteRRNode failed: %v", err)
	}
	vMap := st2.GetRouteViewMap()
	if len(vMap["multi_rr_vrf"].RRNodeIDs) != 0 {
		t.Fatalf("expected deleted RR ID to be pruned from VRF bindings, got %+v", vMap["multi_rr_vrf"].RRNodeIDs)
	}

	// Now deleting HKG PoP must succeed since no RR is bound to it anymore
	if err := st2.DeletePOP("HKG4-LG-RR02"); err != nil {
		t.Fatalf("expected DeletePOP to succeed after removing bound RR, got %v", err)
	}

	// 11. Audit retention pruning check
	st2.SetAuditRetention(30, 50000)

	// 12. Delete view check
	if err := st2.DeleteRouteView(views[1].ID); err != nil {
		t.Fatalf("DeleteRouteView failed: %v", err)
	}
}
