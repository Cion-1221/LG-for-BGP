package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"lg-for-bgp/internal/models"
)

// Note: BGP routing tables (RIBs) are NOT stored in SQLite.
// All BGP routes and routing tables reside strictly in each RR's in-memory RIBs.
// SQLite only stores system settings, PoP groups, VRF views, RR node endpoints, user accounts, and audit logs.
const sqliteSchemaDDL = `
CREATE TABLE IF NOT EXISTS lg_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,
    access_mode TEXT NOT NULL DEFAULT 'public',
    admin_secret_slug TEXT NOT NULL DEFAULT 'console',
    public_allowed_views TEXT NOT NULL DEFAULT '[]',
    default_rr_node TEXT NOT NULL DEFAULT 'auto',
    default_engine TEXT NOT NULL DEFAULT 'gobgp',
    cache_ttl_seconds INTEGER NOT NULL DEFAULT 30,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    organization_name TEXT NOT NULL DEFAULT 'BGP Looking Glass Portal',
    favicon_icon TEXT NOT NULL DEFAULT '',
    portal_logo TEXT NOT NULL DEFAULT '',
    primary_asn INTEGER NOT NULL DEFAULT 65000,
    datacenter_code TEXT NOT NULL DEFAULT 'CORE-POP-01',
    allow_raw_output INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lg_vrfs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vrf_name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'auto',
    pop TEXT NOT NULL DEFAULT 'all',
    rr_node_ids TEXT NOT NULL DEFAULT '[]',
    juniper_source_ipv4 TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS lg_pops (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 10
);

CREATE TABLE IF NOT EXISTS lg_rr_nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    engine_type TEXT NOT NULL DEFAULT 'gobgp',
    loopback_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    agent_token TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'primary',
    enabled INTEGER NOT NULL DEFAULT 1,
    healthy INTEGER NOT NULL DEFAULT 1,
    last_checked TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lg_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    company TEXT NOT NULL,
    customer_asn INTEGER NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'customer',
    allowed_views TEXT NOT NULL DEFAULT '[]',
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    enabled INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_login_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS lg_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    query_type TEXT NULL,
    target TEXT NULL,
    views TEXT NULL,
    rr_node TEXT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON lg_audit_logs (timestamp DESC);
`

func extractSQLitePath(raw string) string {
	v := strings.TrimSpace(raw)
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(lower, "sqlite://"):
		v = v[len("sqlite://"):]
	case strings.HasPrefix(lower, "sqlite3://"):
		v = v[len("sqlite3://"):]
	case strings.HasPrefix(lower, "sqlite:"):
		v = v[len("sqlite:"):]
	case strings.HasPrefix(lower, "sqlite3:"):
		v = v[len("sqlite3:"):]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "./data/lg.db"
	}
	return v
}

func formatSQLiteTime(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseSQLiteTime(raw string) time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *AppStore) initSQLite(rawDSN string) error {
	dbPath := extractSQLitePath(rawDSN)
	isMemory := strings.EqualFold(dbPath, ":memory:") || strings.Contains(strings.ToLower(dbPath), "mode=memory")
	if !isMemory {
		cleanFile := dbPath
		if idx := strings.Index(cleanFile, "?"); idx >= 0 {
			cleanFile = cleanFile[:idx]
		}
		dir := filepath.Dir(cleanFile)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create SQLite directory %s: %w", dir, err)
			}
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database %s: %w", dbPath, err)
	}
	// Single connection prevents SQLITE_BUSY under concurrent Go goroutines while keeping WAL fast.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to ping SQLite database %s: %w", dbPath, err)
	}

	// Apply safe production pragmas (WAL + busy_timeout). Non-fatal if an exotic FS rejects WAL.
	_, _ = db.Exec("PRAGMA busy_timeout = 5000;")
	if !isMemory {
		_, _ = db.Exec("PRAGMA journal_mode = WAL;")
	}
	_, _ = db.Exec("PRAGMA synchronous = NORMAL;")
	_, _ = db.Exec("PRAGMA foreign_keys = ON;")

	s.db = db
	s.dbDriver = "sqlite"

	for _, stmt := range splitSQLStatements(sqliteSchemaDDL) {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		if _, err := s.db.Exec(trimmed); err != nil {
			_ = db.Close()
			s.db = nil
			return fmt.Errorf("SQLite schema migration failed: %w", err)
		}
	}
	// Idempotent online migrations for pre-existing SQLite databases
	_, _ = s.db.Exec("ALTER TABLE lg_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
	_, _ = s.db.Exec("ALTER TABLE lg_vrfs ADD COLUMN pop TEXT NOT NULL DEFAULT 'all'")
	_, _ = s.db.Exec("ALTER TABLE lg_vrfs ADD COLUMN rr_node_ids TEXT NOT NULL DEFAULT '[]'")
	_, _ = s.db.Exec("ALTER TABLE lg_rr_nodes ADD COLUMN agent_token TEXT NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE lg_settings ADD COLUMN favicon_icon TEXT NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE lg_settings ADD COLUMN portal_logo TEXT NOT NULL DEFAULT ''")

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM lg_settings").Scan(&count); err != nil {
		return err
	}

	if count == 0 {
		log.Printf("[DB] Seeding initial default settings and accounts into SQLite (%s)...", dbPath)
		s.data = defaultInitialData()
		if err := s.syncAllToSQLiteLocked(); err != nil {
			return fmt.Errorf("failed to seed SQLite database: %w", err)
		}
		return nil
	}

	log.Printf("[DB] Loading settings and user accounts from SQLite (%s)...", dbPath)
	s.data = defaultInitialData()
	return s.loadFromSQLiteLocked()
}

func (s *AppStore) syncAllToSQLiteLocked() error {
	if s.db == nil {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	pubViewsJSON, _ := json.Marshal(s.data.Settings.PublicAllowedViews)
	_, err = tx.Exec(`
		INSERT INTO lg_settings (
			id, access_mode, admin_secret_slug, public_allowed_views, default_rr_node,
			default_engine, cache_ttl_seconds, rate_limit_per_minute, organization_name,
			favicon_icon, portal_logo, primary_asn, datacenter_code, allow_raw_output, updated_at
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			access_mode=excluded.access_mode,
			admin_secret_slug=excluded.admin_secret_slug,
			public_allowed_views=excluded.public_allowed_views,
			default_rr_node=excluded.default_rr_node,
			default_engine=excluded.default_engine,
			cache_ttl_seconds=excluded.cache_ttl_seconds,
			rate_limit_per_minute=excluded.rate_limit_per_minute,
			organization_name=excluded.organization_name,
			favicon_icon=excluded.favicon_icon,
			portal_logo=excluded.portal_logo,
			primary_asn=excluded.primary_asn,
			datacenter_code=excluded.datacenter_code,
			allow_raw_output=excluded.allow_raw_output,
			updated_at=excluded.updated_at
	`,
		string(s.data.Settings.AccessMode),
		s.data.Settings.AdminSecretSlug,
		string(pubViewsJSON),
		s.data.Settings.DefaultRRNode,
		s.data.Settings.DefaultEngine,
		s.data.Settings.CacheTTLSeconds,
		s.data.Settings.RateLimitPerMinute,
		s.data.Settings.OrganizationName,
		s.data.Settings.FaviconIcon,
		s.data.Settings.PortalLogo,
		s.data.Settings.PrimaryASN,
		s.data.Settings.DatacenterCode,
		boolToInt(s.data.Settings.AllowRawOutput),
		formatSQLiteTime(s.data.Settings.UpdatedAt),
	)
	if err != nil {
		return err
	}

	for idx, v := range s.data.RouteViews {
		vrfName := v.VRFName
		if vrfName == "" {
			vrfName = v.JunosContextName
		}
		vType := v.Type
		if vType == "" {
			vType = "auto"
		}
		vPop := strings.TrimSpace(v.POP)
		if vPop == "" {
			vPop = "all"
		}
		rrIDs := v.RRNodeIDs
		if rrIDs == nil {
			rrIDs = []string{}
		}
		rrIDsJSON, _ := json.Marshal(rrIDs)
		_, err := tx.Exec(`
			INSERT INTO lg_vrfs (id, name, vrf_name, type, pop, rr_node_ids, juniper_source_ipv4, description, sort_order)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name=excluded.name,
				vrf_name=excluded.vrf_name,
				type=excluded.type,
				pop=excluded.pop,
				rr_node_ids=excluded.rr_node_ids,
				juniper_source_ipv4=excluded.juniper_source_ipv4,
				description=excluded.description,
				sort_order=excluded.sort_order
		`, string(v.ID), v.Name, vrfName, vType, vPop, string(rrIDsJSON), v.JuniperSourceIPv4, v.Description, idx)
		if err != nil {
			return err
		}
	}

	for idx, p := range s.data.POPs {
		order := p.SortOrder
		if order <= 0 {
			order = idx + 1
		}
		_, err := tx.Exec(`
			INSERT INTO lg_pops (id, name, description, sort_order)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name=excluded.name,
				description=excluded.description,
				sort_order=excluded.sort_order
		`, p.ID, p.Name, p.Description, order)
		if err != nil {
			return err
		}
	}

	for _, n := range s.data.RRNodes {
		_, err := tx.Exec(`
			INSERT INTO lg_rr_nodes (
				id, name, location, engine_type, loopback_ip, endpoint, agent_token, role, enabled, healthy, last_checked
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name=excluded.name,
				location=excluded.location,
				engine_type=excluded.engine_type,
				loopback_ip=excluded.loopback_ip,
				endpoint=excluded.endpoint,
				agent_token=excluded.agent_token,
				role=excluded.role,
				enabled=excluded.enabled,
				healthy=excluded.healthy,
				last_checked=excluded.last_checked
		`,
			n.ID, n.Name, n.Location, n.EngineType, n.LoopbackIP, n.Endpoint, n.AgentToken, n.Role,
			boolToInt(n.Enabled), boolToInt(n.Healthy), n.LastChecked,
		)
		if err != nil {
			return err
		}
	}

	for _, u := range s.data.Users {
		viewsJSON, _ := json.Marshal(u.AllowedViews)
		var lastLogin interface{}
		if u.LastLoginAt != nil {
			lastLogin = formatSQLiteTime(*u.LastLoginAt)
		}
		_, err := tx.Exec(`
			INSERT INTO lg_users (
				id, username, password_hash, display_name, company, customer_asn,
				role, allowed_views, rate_limit_per_minute, enabled, must_change_password, notes, created_at, last_login_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				username=excluded.username,
				password_hash=excluded.password_hash,
				display_name=excluded.display_name,
				company=excluded.company,
				customer_asn=excluded.customer_asn,
				role=excluded.role,
				allowed_views=excluded.allowed_views,
				rate_limit_per_minute=excluded.rate_limit_per_minute,
				enabled=excluded.enabled,
				must_change_password=excluded.must_change_password,
				notes=excluded.notes,
				last_login_at=excluded.last_login_at
		`,
			u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Company, u.CustomerASN,
			u.Role, string(viewsJSON), u.RateLimitPerMinute, boolToInt(u.Enabled),
			boolToInt(u.MustChangePassword), u.Notes, formatSQLiteTime(u.CreatedAt), lastLogin,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *AppStore) loadFromSQLiteLocked() error {
	var pubViewsRaw string
	var modeStr string
	var allowRawInt int
	var updatedAtRaw string
	err := s.db.QueryRow(`
		SELECT access_mode, admin_secret_slug, public_allowed_views, default_rr_node,
		       default_engine, cache_ttl_seconds, rate_limit_per_minute, organization_name,
		       COALESCE(favicon_icon, ''), COALESCE(portal_logo, ''),
		       primary_asn, datacenter_code, allow_raw_output, updated_at
		FROM lg_settings WHERE id = 1
	`).Scan(
		&modeStr,
		&s.data.Settings.AdminSecretSlug,
		&pubViewsRaw,
		&s.data.Settings.DefaultRRNode,
		&s.data.Settings.DefaultEngine,
		&s.data.Settings.CacheTTLSeconds,
		&s.data.Settings.RateLimitPerMinute,
		&s.data.Settings.OrganizationName,
		&s.data.Settings.FaviconIcon,
		&s.data.Settings.PortalLogo,
		&s.data.Settings.PrimaryASN,
		&s.data.Settings.DatacenterCode,
		&allowRawInt,
		&updatedAtRaw,
	)
	if err != nil {
		return err
	}
	s.data.Settings.AccessMode = models.AccessMode(modeStr)
	s.data.Settings.AllowRawOutput = allowRawInt != 0
	s.data.Settings.UpdatedAt = parseSQLiteTime(updatedAtRaw)
	_ = json.Unmarshal([]byte(pubViewsRaw), &s.data.Settings.PublicAllowedViews)

	// Load VRF Configurations
	vRows, err := s.db.Query(`
		SELECT id, name, vrf_name, type, COALESCE(pop, 'all'), COALESCE(rr_node_ids, ''), juniper_source_ipv4, COALESCE(description, '')
		FROM lg_vrfs ORDER BY sort_order ASC, id ASC
	`)
	if err == nil {
		defer vRows.Close()
		var loadedViews []models.RouteViewMeta
		for vRows.Next() {
			var v models.RouteViewMeta
			var idStr, rrIDsRaw string
			if err := vRows.Scan(&idStr, &v.Name, &v.VRFName, &v.Type, &v.POP, &rrIDsRaw, &v.JuniperSourceIPv4, &v.Description); err == nil {
				v.ID = models.RouteViewID(idStr)
				if strings.TrimSpace(rrIDsRaw) != "" {
					_ = json.Unmarshal([]byte(rrIDsRaw), &v.RRNodeIDs)
				}
				normalizeLoadedRouteView(&v)
				loadedViews = append(loadedViews, v)
			}
		}
		s.data.RouteViews = loadedViews
	}

	// Load POPs
	pRows, err := s.db.Query(`SELECT id, name, COALESCE(description, ''), sort_order FROM lg_pops ORDER BY sort_order ASC, id ASC`)
	if err == nil {
		defer pRows.Close()
		s.data.POPs = nil
		for pRows.Next() {
			var p models.POPGroup
			if err := pRows.Scan(&p.ID, &p.Name, &p.Description, &p.SortOrder); err == nil {
				s.data.POPs = append(s.data.POPs, p)
			}
		}
	}

	// Load RRNodes
	rRows, err := s.db.Query(`
		SELECT id, name, location, engine_type, loopback_ip, endpoint, COALESCE(agent_token, ''), role, enabled, healthy, last_checked
		FROM lg_rr_nodes ORDER BY id ASC
	`)
	if err != nil {
		return err
	}
	defer rRows.Close()
	s.data.RRNodes = nil
	for rRows.Next() {
		var n models.RRNodeConfig
		var enabledInt, healthyInt int
		if err := rRows.Scan(
			&n.ID, &n.Name, &n.Location, &n.EngineType, &n.LoopbackIP,
			&n.Endpoint, &n.AgentToken, &n.Role, &enabledInt, &healthyInt, &n.LastChecked,
		); err != nil {
			return err
		}
		n.Enabled = enabledInt != 0
		n.Healthy = healthyInt != 0
		s.data.RRNodes = append(s.data.RRNodes, n)
	}
	s.ensurePOPsFromRRNodesLocked()
	migrated := s.migrateLegacyViewBindingsLocked()

	// Load Users
	uRows, err := s.db.Query(`
		SELECT id, username, password_hash, display_name, company, customer_asn,
		       role, allowed_views, rate_limit_per_minute, enabled, must_change_password, COALESCE(notes, ''), created_at, last_login_at
		FROM lg_users ORDER BY created_at ASC
	`)
	if err != nil {
		return err
	}
	defer uRows.Close()
	s.data.Users = nil
	for uRows.Next() {
		var u models.UserAccount
		var viewsRaw string
		var enabledInt, mustChangeInt int
		var createdAtRaw string
		var lastLoginRaw sql.NullString
		if err := uRows.Scan(
			&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Company, &u.CustomerASN,
			&u.Role, &viewsRaw, &u.RateLimitPerMinute, &enabledInt, &mustChangeInt, &u.Notes, &createdAtRaw, &lastLoginRaw,
		); err != nil {
			return err
		}
		u.Enabled = enabledInt != 0
		u.MustChangePassword = mustChangeInt != 0
		u.CreatedAt = parseSQLiteTime(createdAtRaw)
		_ = json.Unmarshal([]byte(viewsRaw), &u.AllowedViews)
		if lastLoginRaw.Valid && strings.TrimSpace(lastLoginRaw.String) != "" {
			t := parseSQLiteTime(lastLoginRaw.String)
			if !t.IsZero() {
				u.LastLoginAt = &t
			}
		}
		s.data.Users = append(s.data.Users, u)
	}

	if s.pruneStaleViewIDsLocked() {
		_ = s.syncAllowedViewsDBLocked()
	}
	if migrated {
		for idx, v := range s.data.RouteViews {
			_ = s.upsertRouteViewDBLocked(v, idx)
		}
	}

	// Load recent 1000 Audit Logs
	aRows, err := s.db.Query(`
		SELECT timestamp, username, client_ip, action, COALESCE(query_type,''), COALESCE(target,''), COALESCE(views,''), COALESCE(rr_node,''), duration_ms
		FROM lg_audit_logs ORDER BY id DESC LIMIT 1000
	`)
	if err == nil {
		defer aRows.Close()
		s.data.AuditLogs = nil
		for aRows.Next() {
			var a models.AuditLogEntry
			var tsRaw string
			if err := aRows.Scan(&tsRaw, &a.Username, &a.ClientIP, &a.Action, &a.QueryType, &a.Target, &a.Views, &a.RRNode, &a.DurationMs); err == nil {
				a.Timestamp = parseSQLiteTime(tsRaw)
				s.data.AuditLogs = append(s.data.AuditLogs, a)
			}
		}
	}

	return nil
}
