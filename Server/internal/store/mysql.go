// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"lg-for-bgp/internal/models"
)

// Note: BGP routing tables (RIBs) are NOT stored in MySQL/MariaDB.
// All BGP routes and routing tables reside strictly in each RR's in-memory RIBs.
// MySQL/MariaDB only stores system settings, PoP groups, VRF views, RR node endpoints, user accounts, and audit logs.
const mysqlSchemaDDL = `
CREATE TABLE IF NOT EXISTS lg_settings (
    id INT PRIMARY KEY DEFAULT 1,
    access_mode VARCHAR(32) NOT NULL DEFAULT 'public',
    admin_secret_slug VARCHAR(128) NOT NULL DEFAULT 'console',
    public_allowed_views JSON NOT NULL,
    default_rr_node VARCHAR(64) NOT NULL DEFAULT 'auto',
    default_engine VARCHAR(32) NOT NULL DEFAULT 'gobgp',
    cache_ttl_seconds INT NOT NULL DEFAULT 30,
    rate_limit_per_minute INT NOT NULL DEFAULT 60,
    organization_name VARCHAR(128) NOT NULL DEFAULT 'BGP Looking Glass Portal',
    favicon_icon MEDIUMTEXT NULL,
    portal_logo MEDIUMTEXT NULL,
    primary_asn INT UNSIGNED NOT NULL DEFAULT 65000,
    datacenter_code VARCHAR(64) NOT NULL DEFAULT 'CORE-POP-01',
    allow_raw_output TINYINT(1) NOT NULL DEFAULT 1,
    updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lg_vrfs (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    vrf_name VARCHAR(128) NOT NULL,
    type VARCHAR(32) NOT NULL DEFAULT 'auto',
    pop VARCHAR(64) NOT NULL DEFAULT 'all',
    rr_node_ids JSON NULL,
    juniper_source_ipv4 VARCHAR(64) NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    sort_order INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lg_pops (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    sort_order INT NOT NULL DEFAULT 10
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lg_rr_nodes (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    location VARCHAR(128) NOT NULL,
    engine_type VARCHAR(32) NOT NULL DEFAULT 'gobgp',
    loopback_ip VARCHAR(64) NOT NULL,
    endpoint VARCHAR(128) NOT NULL,
    agent_token VARCHAR(255) NOT NULL DEFAULT '',
    role VARCHAR(32) NOT NULL DEFAULT 'primary',
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    healthy TINYINT(1) NOT NULL DEFAULT 1,
    last_checked VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lg_users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    company VARCHAR(128) NOT NULL,
    customer_asn INT UNSIGNED NOT NULL DEFAULT 0,
    role VARCHAR(32) NOT NULL DEFAULT 'customer',
    allowed_views JSON NOT NULL,
    rate_limit_per_minute INT NOT NULL DEFAULT 60,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    notes TEXT,
    created_at DATETIME NOT NULL,
    last_login_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lg_audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    username VARCHAR(64) NOT NULL,
    client_ip VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    query_type VARCHAR(32) NULL,
    target VARCHAR(128) NULL,
    views VARCHAR(255) NULL,
    rr_node VARCHAR(128) NULL,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    INDEX idx_audit_timestamp (timestamp DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

func (s *AppStore) initMySQL(dsn string) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open MySQL/MariaDB connection: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to ping MySQL/MariaDB server: %w", err)
	}
	s.db = db
	s.dbDriver = "mysql"

	stmts := splitSQLStatements(mysqlSchemaDDL)
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("schema migration failed: %w", err)
		}
	}
	// Automatic online migration for existing databases
	_, _ = s.db.Exec("ALTER TABLE lg_users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0")
	_, _ = s.db.Exec("ALTER TABLE lg_vrfs ADD COLUMN pop VARCHAR(64) NOT NULL DEFAULT 'all'")
	_, _ = s.db.Exec("ALTER TABLE lg_vrfs ADD COLUMN rr_node_ids JSON NULL")
	_, _ = s.db.Exec("ALTER TABLE lg_rr_nodes ADD COLUMN agent_token VARCHAR(255) NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE lg_settings ADD COLUMN favicon_icon MEDIUMTEXT NULL")
	_, _ = s.db.Exec("ALTER TABLE lg_settings ADD COLUMN portal_logo MEDIUMTEXT NULL")

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM lg_settings").Scan(&count); err != nil {
		return err
	}

	if count == 0 {
		log.Println("[DB] Seeding initial default settings and accounts into MySQL/MariaDB...")
		s.data = defaultInitialData()
		if err := s.syncAllToMySQLLocked(); err != nil {
			return fmt.Errorf("failed to seed MySQL/MariaDB: %w", err)
		}
		return nil
	}

	log.Println("[DB] Loading settings and user accounts from MySQL/MariaDB...")
	s.data = defaultInitialData()
	return s.loadFromMySQLLocked()
}

func splitSQLStatements(raw string) []string {
	var out []string
	var cur string
	for _, line := range splitLines(raw) {
		cur += line + "\n"
		if len(line) > 0 && line[len(line)-1] == ';' {
			out = append(out, cur)
			cur = ""
		}
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func (s *AppStore) syncAllToMySQLLocked() error {
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
		ON DUPLICATE KEY UPDATE
			access_mode=VALUES(access_mode),
			admin_secret_slug=VALUES(admin_secret_slug),
			public_allowed_views=VALUES(public_allowed_views),
			default_rr_node=VALUES(default_rr_node),
			default_engine=VALUES(default_engine),
			cache_ttl_seconds=VALUES(cache_ttl_seconds),
			rate_limit_per_minute=VALUES(rate_limit_per_minute),
			organization_name=VALUES(organization_name),
			favicon_icon=VALUES(favicon_icon),
			portal_logo=VALUES(portal_logo),
			primary_asn=VALUES(primary_asn),
			datacenter_code=VALUES(datacenter_code),
			allow_raw_output=VALUES(allow_raw_output),
			updated_at=VALUES(updated_at)
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
		s.data.Settings.AllowRawOutput,
		s.data.Settings.UpdatedAt,
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
			ON DUPLICATE KEY UPDATE
				name=VALUES(name), vrf_name=VALUES(vrf_name), type=VALUES(type), pop=VALUES(pop),
				rr_node_ids=VALUES(rr_node_ids), juniper_source_ipv4=VALUES(juniper_source_ipv4),
				description=VALUES(description), sort_order=VALUES(sort_order)
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
			ON DUPLICATE KEY UPDATE
				name=VALUES(name), description=VALUES(description), sort_order=VALUES(sort_order)
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
			ON DUPLICATE KEY UPDATE
				name=VALUES(name), location=VALUES(location), engine_type=VALUES(engine_type),
				loopback_ip=VALUES(loopback_ip), endpoint=VALUES(endpoint), agent_token=VALUES(agent_token),
				role=VALUES(role), enabled=VALUES(enabled), healthy=VALUES(healthy), last_checked=VALUES(last_checked)
		`,
			n.ID, n.Name, n.Location, n.EngineType, n.LoopbackIP, n.Endpoint, n.AgentToken, n.Role, n.Enabled, n.Healthy, n.LastChecked,
		)
		if err != nil {
			return err
		}
	}

	for _, u := range s.data.Users {
		viewsJSON, _ := json.Marshal(u.AllowedViews)
		_, err := tx.Exec(`
			INSERT INTO lg_users (
				id, username, password_hash, display_name, company, customer_asn,
				role, allowed_views, rate_limit_per_minute, enabled, must_change_password, notes, created_at, last_login_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				username=VALUES(username), password_hash=VALUES(password_hash),
				display_name=VALUES(display_name), company=VALUES(company),
				customer_asn=VALUES(customer_asn), role=VALUES(role),
				allowed_views=VALUES(allowed_views), rate_limit_per_minute=VALUES(rate_limit_per_minute),
				enabled=VALUES(enabled), must_change_password=VALUES(must_change_password),
				notes=VALUES(notes), last_login_at=VALUES(last_login_at)
		`,
			u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Company, u.CustomerASN,
			u.Role, string(viewsJSON), u.RateLimitPerMinute, u.Enabled, u.MustChangePassword, u.Notes, u.CreatedAt, u.LastLoginAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *AppStore) loadFromMySQLLocked() error {
	var pubViewsRaw string
	var modeStr string
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
		&s.data.Settings.AllowRawOutput,
		&s.data.Settings.UpdatedAt,
	)
	if err != nil {
		return err
	}
	s.data.Settings.AccessMode = models.AccessMode(modeStr)
	_ = json.Unmarshal([]byte(pubViewsRaw), &s.data.Settings.PublicAllowedViews)

	// Load VRF Configurations (Name, VRFName, Type, POP, RRNodeIDs)
	vRows, err := s.db.Query(`
		SELECT id, name, vrf_name, type, COALESCE(pop, 'all'), COALESCE(CAST(rr_node_ids AS CHAR), ''), juniper_source_ipv4, description
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
	pRows, err := s.db.Query(`SELECT id, name, description, sort_order FROM lg_pops ORDER BY sort_order ASC, id ASC`)
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
		if err := rRows.Scan(
			&n.ID, &n.Name, &n.Location, &n.EngineType, &n.LoopbackIP,
			&n.Endpoint, &n.AgentToken, &n.Role, &n.Enabled, &n.Healthy, &n.LastChecked,
		); err != nil {
			return err
		}
		s.data.RRNodes = append(s.data.RRNodes, n)
	}
	s.ensurePOPsFromRRNodesLocked()
	migrated := s.migrateLegacyViewBindingsLocked()

	// Load Users
	uRows, err := s.db.Query(`
		SELECT id, username, password_hash, display_name, company, customer_asn,
		       role, allowed_views, rate_limit_per_minute, enabled, must_change_password, notes, created_at, last_login_at
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
		var lastLogin sql.NullTime
		if err := uRows.Scan(
			&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Company, &u.CustomerASN,
			&u.Role, &viewsRaw, &u.RateLimitPerMinute, &u.Enabled, &u.MustChangePassword, &u.Notes, &u.CreatedAt, &lastLogin,
		); err != nil {
			return err
		}
		_ = json.Unmarshal([]byte(viewsRaw), &u.AllowedViews)
		if lastLogin.Valid {
			t := lastLogin.Time
			u.LastLoginAt = &t
		}
		s.data.Users = append(s.data.Users, u)
	}

	// Automatically prune any deleted/stale VRF IDs incrementally
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
			if err := aRows.Scan(&a.Timestamp, &a.Username, &a.ClientIP, &a.Action, &a.QueryType, &a.Target, &a.Views, &a.RRNode, &a.DurationMs); err == nil {
				s.data.AuditLogs = append(s.data.AuditLogs, a)
			}
		}
	}

	return nil
}
