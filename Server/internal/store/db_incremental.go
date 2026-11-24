// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"encoding/json"
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
				default_engine, cache_ttl_seconds, rate_limit_per_minute,
				max_filter_routes_ipv4, max_filter_routes_ipv6, organization_name,
				favicon_icon, portal_logo, primary_asn, datacenter_code, allow_raw_output, updated_at
			) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				access_mode=excluded.access_mode,
				admin_secret_slug=excluded.admin_secret_slug,
				public_allowed_views=excluded.public_allowed_views,
				default_rr_node=excluded.default_rr_node,
				default_engine=excluded.default_engine,
				cache_ttl_seconds=excluded.cache_ttl_seconds,
				rate_limit_per_minute=excluded.rate_limit_per_minute,
				max_filter_routes_ipv4=excluded.max_filter_routes_ipv4,
				max_filter_routes_ipv6=excluded.max_filter_routes_ipv6,
				organization_name=excluded.organization_name,
				favicon_icon=excluded.favicon_icon,
				portal_logo=excluded.portal_logo,
				primary_asn=excluded.primary_asn,
				datacenter_code=excluded.datacenter_code,
				allow_raw_output=excluded.allow_raw_output,
				updated_at=excluded.updated_at
		`
	} else {
		query = `
			INSERT INTO lg_settings (
				id, access_mode, admin_secret_slug, public_allowed_views, default_rr_node,
				default_engine, cache_ttl_seconds, rate_limit_per_minute,
				max_filter_routes_ipv4, max_filter_routes_ipv6, organization_name,
				favicon_icon, portal_logo, primary_asn, datacenter_code, allow_raw_output, updated_at
			) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				access_mode=VALUES(access_mode),
				admin_secret_slug=VALUES(admin_secret_slug),
				public_allowed_views=VALUES(public_allowed_views),
				default_rr_node=VALUES(default_rr_node),
				default_engine=VALUES(default_engine),
				cache_ttl_seconds=VALUES(cache_ttl_seconds),
				rate_limit_per_minute=VALUES(rate_limit_per_minute),
				max_filter_routes_ipv4=VALUES(max_filter_routes_ipv4),
				max_filter_routes_ipv6=VALUES(max_filter_routes_ipv6),
				organization_name=VALUES(organization_name),
				favicon_icon=VALUES(favicon_icon),
				portal_logo=VALUES(portal_logo),
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
		s.data.Settings.MaxFilterRoutesV4,
		s.data.Settings.MaxFilterRoutesV6,
		s.data.Settings.OrganizationName,
		s.data.Settings.FaviconIcon,
		s.data.Settings.PortalLogo,
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
			INSERT INTO lg_vrfs (id, name, vrf_name, type, pop, rr_node_ids, juniper_source_ipv4, bird_table_v6, description, sort_order)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name=excluded.name,
				vrf_name=excluded.vrf_name,
				type=excluded.type,
				pop=excluded.pop,
				rr_node_ids=excluded.rr_node_ids,
				juniper_source_ipv4=excluded.juniper_source_ipv4,
				bird_table_v6=excluded.bird_table_v6,
				description=excluded.description,
				sort_order=excluded.sort_order
		`
	} else {
		query = `
			INSERT INTO lg_vrfs (id, name, vrf_name, type, pop, rr_node_ids, juniper_source_ipv4, bird_table_v6, description, sort_order)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				name=VALUES(name),
				vrf_name=VALUES(vrf_name),
				type=VALUES(type),
				pop=VALUES(pop),
				rr_node_ids=VALUES(rr_node_ids),
				juniper_source_ipv4=VALUES(juniper_source_ipv4),
				bird_table_v6=VALUES(bird_table_v6),
				description=VALUES(description),
				sort_order=VALUES(sort_order)
		`
	}
	_, err := s.db.Exec(query, string(v.ID), v.Name, vrfName, vType, vPop, string(rrIDsJSON), v.JuniperSourceIPv4, v.BirdTableV6, v.Description, sortOrder)
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
