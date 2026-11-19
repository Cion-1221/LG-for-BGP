package store

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
)

func (s *AppStore) dbTimeArg(t time.Time) interface{} {
	if s.dbDriver == "sqlite" {
		return formatSQLiteTime(t)
	}
	return t
}

func (s *AppStore) dbNullableTimeArg(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	if s.dbDriver == "sqlite" {
		return formatSQLiteTime(*t)
	}
	return *t
}

func (s *AppStore) dbBoolArg(b bool) interface{} {
	if s.dbDriver == "sqlite" {
		return boolToInt(b)
	}
	return b
}

func (s *AppStore) upsertSettingsDBLocked() error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	pubViewsJSON, _ := json.Marshal(s.data.Settings.PublicAllowedViews)
	var query string
	if s.dbDriver == "sqlite" {
		query = `
			INSERT INTO lg_settings (
				id, access_mode, admin_secret_slug, public_allowed_views, default_rr_node,
				default_engine, cache_ttl_seconds, rate_limit_per_minute, organization_name,
				primary_asn, datacenter_code, allow_raw_output, updated_at
			) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				access_mode=excluded.access_mode,
				admin_secret_slug=excluded.admin_secret_slug,
				public_allowed_views=excluded.public_allowed_views,
				default_rr_node=excluded.default_rr_node,
				default_engine=excluded.default_engine,
				cache_ttl_seconds=excluded.cache_ttl_seconds,
				rate_limit_per_minute=excluded.rate_limit_per_minute,
				organization_name=excluded.organization_name,
				primary_asn=excluded.primary_asn,
				datacenter_code=excluded.datacenter_code,
				allow_raw_output=excluded.allow_raw_output,
				updated_at=excluded.updated_at
		`
	} else {
		query = `
			INSERT INTO lg_settings (
				id, access_mode, admin_secret_slug, public_allowed_views, default_rr_node,
				default_engine, cache_ttl_seconds, rate_limit_per_minute, organization_name,
				primary_asn, datacenter_code, allow_raw_output, updated_at
			) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				access_mode=VALUES(access_mode),
				admin_secret_slug=VALUES(admin_secret_slug),
				public_allowed_views=VALUES(public_allowed_views),
				default_rr_node=VALUES(default_rr_node),
				default_engine=VALUES(default_engine),
				cache_ttl_seconds=VALUES(cache_ttl_seconds),
				rate_limit_per_minute=VALUES(rate_limit_per_minute),
				organization_name=VALUES(organization_name),
				primary_asn=VALUES(primary_asn),
				datacenter_code=VALUES(datacenter_code),
				allow_raw_output=VALUES(allow_raw_output),
				updated_at=VALUES(updated_at)
		`
	}
	_, err := s.db.Exec(query,
		string(s.data.Settings.AccessMode),
		s.data.Settings.AdminSecretSlug,
		string(pubViewsJSON),
		s.data.Settings.DefaultRRNode,
		s.data.Settings.DefaultEngine,
		s.data.Settings.CacheTTLSeconds,
		s.data.Settings.RateLimitPerMinute,
		s.data.Settings.OrganizationName,
		s.data.Settings.PrimaryASN,
		s.data.Settings.DatacenterCode,
		s.dbBoolArg(s.data.Settings.AllowRawOutput),
		s.dbTimeArg(s.data.Settings.UpdatedAt),
	)
	return err
}

func (s *AppStore) upsertRouteViewDBLocked(v models.RouteViewMeta, sortOrder int) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
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

	var query string
	if s.dbDriver == "sqlite" {
		query = `
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
		`
	} else {
		query = `
			INSERT INTO lg_vrfs (id, name, vrf_name, type, pop, rr_node_ids, juniper_source_ipv4, description, sort_order)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				name=VALUES(name),
				vrf_name=VALUES(vrf_name),
				type=VALUES(type),
				pop=VALUES(pop),
				rr_node_ids=VALUES(rr_node_ids),
				juniper_source_ipv4=VALUES(juniper_source_ipv4),
				description=VALUES(description),
				sort_order=VALUES(sort_order)
		`
	}
	_, err := s.db.Exec(query, string(v.ID), v.Name, vrfName, vType, vPop, string(rrIDsJSON), v.JuniperSourceIPv4, v.Description, sortOrder)
	return err
}

func (s *AppStore) upsertPOPDBLocked(p models.POPGroup, sortOrder int) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	order := p.SortOrder
	if order <= 0 {
		order = sortOrder
	}
	var query string
	if s.dbDriver == "sqlite" {
		query = `
			INSERT INTO lg_pops (id, name, description, sort_order)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name=excluded.name,
				description=excluded.description,
				sort_order=excluded.sort_order
		`
	} else {
		query = `
			INSERT INTO lg_pops (id, name, description, sort_order)
			VALUES (?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				name=VALUES(name),
				description=VALUES(description),
				sort_order=VALUES(sort_order)
		`
	}
	_, err := s.db.Exec(query, p.ID, p.Name, p.Description, order)
	return err
}

func (s *AppStore) upsertRRNodeDBLocked(n models.RRNodeConfig) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	var query string
	if s.dbDriver == "sqlite" {
		query = `
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
		`
	} else {
		query = `
			INSERT INTO lg_rr_nodes (
				id, name, location, engine_type, loopback_ip, endpoint, agent_token, role, enabled, healthy, last_checked
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				name=VALUES(name),
				location=VALUES(location),
				engine_type=VALUES(engine_type),
				loopback_ip=VALUES(loopback_ip),
				endpoint=VALUES(endpoint),
				agent_token=VALUES(agent_token),
				role=VALUES(role),
				enabled=VALUES(enabled),
				healthy=VALUES(healthy),
				last_checked=VALUES(last_checked)
		`
	}
	_, err := s.db.Exec(query,
		n.ID, n.Name, n.Location, n.EngineType, n.LoopbackIP, n.Endpoint, n.AgentToken, n.Role,
		s.dbBoolArg(n.Enabled), s.dbBoolArg(n.Healthy), n.LastChecked,
	)
	return err
}

func (s *AppStore) updateRRNodeHealthDBLocked(id string, healthy bool, lastChecked string) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	_, err := s.db.Exec(`UPDATE lg_rr_nodes SET healthy = ?, last_checked = ? WHERE id = ?`,
		s.dbBoolArg(healthy), lastChecked, id)
	return err
}

func (s *AppStore) upsertUserDBLocked(u models.UserAccount) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	viewsJSON, _ := json.Marshal(u.AllowedViews)
	var query string
	if s.dbDriver == "sqlite" {
		query = `
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
		`
	} else {
		query = `
			INSERT INTO lg_users (
				id, username, password_hash, display_name, company, customer_asn,
				role, allowed_views, rate_limit_per_minute, enabled, must_change_password, notes, created_at, last_login_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				username=VALUES(username),
				password_hash=VALUES(password_hash),
				display_name=VALUES(display_name),
				company=VALUES(company),
				customer_asn=VALUES(customer_asn),
				role=VALUES(role),
				allowed_views=VALUES(allowed_views),
				rate_limit_per_minute=VALUES(rate_limit_per_minute),
				enabled=VALUES(enabled),
				must_change_password=VALUES(must_change_password),
				notes=VALUES(notes),
				last_login_at=VALUES(last_login_at)
		`
	}
	_, err := s.db.Exec(query,
		u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Company, u.CustomerASN,
		u.Role, string(viewsJSON), u.RateLimitPerMinute, s.dbBoolArg(u.Enabled),
		s.dbBoolArg(u.MustChangePassword), u.Notes, s.dbTimeArg(u.CreatedAt), s.dbNullableTimeArg(u.LastLoginAt),
	)
	return err
}

func (s *AppStore) updateUserLastLoginDBLocked(userID string, ts time.Time) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	_, err := s.db.Exec(`UPDATE lg_users SET last_login_at = ? WHERE id = ?`, s.dbTimeArg(ts), userID)
	return err
}

func (s *AppStore) updateUserPasswordDBLocked(userID, passwordHash string, mustChange bool) error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	_, err := s.db.Exec(`UPDATE lg_users SET password_hash = ?, must_change_password = ? WHERE id = ?`,
		passwordHash, s.dbBoolArg(mustChange), userID)
	return err
}

// syncAllowedViewsDBLocked updates only public_allowed_views and user allowed_views incrementally.
func (s *AppStore) syncAllowedViewsDBLocked() error {
	if s.db == nil {
		return s.persistFileLocked()
	}
	pubViewsJSON, _ := json.Marshal(s.data.Settings.PublicAllowedViews)
	if _, err := s.db.Exec(`UPDATE lg_settings SET public_allowed_views = ? WHERE id = 1`, string(pubViewsJSON)); err != nil {
		return err
	}
	for _, u := range s.data.Users {
		viewsJSON, _ := json.Marshal(u.AllowedViews)
		if _, err := s.db.Exec(`UPDATE lg_users SET allowed_views = ? WHERE id = ?`, string(viewsJSON), u.ID); err != nil {
			return err
		}
	}
	return nil
}

// SetAuditRetention configures automatic pruning of old lg_audit_logs rows in SQLite / MySQL.
func (s *AppStore) SetAuditRetention(retentionDays, maxRows int) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if maxRows <= 0 {
		maxRows = 50000
	}
	s.mu.Lock()
	s.auditRetentionDays = retentionDays
	s.auditMaxRows = maxRows
	startLoop := !s.auditCleanerStarted && s.db != nil
	if startLoop {
		s.auditCleanerStarted = true
	}
	s.mu.Unlock()

	if s.db != nil {
		s.PruneAuditLogs()
	}
	if startLoop {
		go s.auditRetentionLoop()
	}
}

func (s *AppStore) auditRetentionLoop() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.PruneAuditLogs()
		}
	}
}

// PruneAuditLogs deletes expired or excess audit log rows from MySQL/MariaDB or SQLite
// to keep database size bounded on long-running deployments (especially VyOS flash storage).
func (s *AppStore) PruneAuditLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	days := s.auditRetentionDays
	if days <= 0 {
		days = 30
	}
	maxRows := s.auditMaxRows
	if maxRows <= 0 {
		maxRows = 50000
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	res1, err := s.db.Exec(`DELETE FROM lg_audit_logs WHERE timestamp < ?`, s.dbTimeArg(cutoff))
	var deleted int64
	if err == nil && res1 != nil {
		if n, e := res1.RowsAffected(); e == nil {
			deleted += n
		}
	}

	// Enforce max row cap (keep newest maxRows by id)
	if s.dbDriver == "sqlite" {
		res2, err2 := s.db.Exec(`
			DELETE FROM lg_audit_logs
			WHERE id NOT IN (SELECT id FROM lg_audit_logs ORDER BY id DESC LIMIT ?)
		`, maxRows)
		if err2 == nil && res2 != nil {
			if n, e := res2.RowsAffected(); e == nil {
				deleted += n
			}
		}
		if deleted > 0 {
			_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		}
	} else {
		// MySQL/MariaDB safe max-id subquery delete
		var thresholdID int64
		errRow := s.db.QueryRow(`SELECT id FROM lg_audit_logs ORDER BY id DESC LIMIT 1 OFFSET ?`, maxRows).Scan(&thresholdID)
		if errRow == nil && thresholdID > 0 {
			res2, err2 := s.db.Exec(`DELETE FROM lg_audit_logs WHERE id <= ?`, thresholdID)
			if err2 == nil && res2 != nil {
				if n, e := res2.RowsAffected(); e == nil {
					deleted += n
				}
			}
		}
	}

	if deleted > 0 {
		log.Printf("[DB] Pruned %d expired/excess audit log rows (retention=%dd, max_rows=%d)", deleted, days, maxRows)
	}
}
