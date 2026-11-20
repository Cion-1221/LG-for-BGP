-- Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
-- ==============================================================================
-- LG-for-BGP Embedded SQLite3 Database Schema Reference
-- Ideal for minimal Linux appliances (e.g., VyOS) or single-node deployments
-- where installing MySQL / MariaDB is unnecessary or unavailable.
--
-- NOTE: lg-server automatically creates the SQLite file, enables WAL mode,
--       initializes all tables below, and seeds the default admin account on
--       first startup — no manual SQL import is required.
--
-- IMPORTANT ARCHITECTURE NOTE:
--   - All BGP routing tables and routes are stored EXCLUSIVELY in each RR's
--     in-memory RIBs (GoBGP Adj-RIB-In / BIRD 2 Tables / FRR Views).
--   - SQLite ONLY stores User Accounts, System Settings, PoP Groups,
--     VRF definitions, RR Node connection configs, and Audit Logs.
-- ==============================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS lg_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,
    access_mode TEXT NOT NULL DEFAULT 'public',
    admin_secret_slug TEXT NOT NULL DEFAULT 'console',
    public_allowed_views TEXT NOT NULL DEFAULT '[]',
    default_rr_node TEXT NOT NULL DEFAULT 'auto',
    default_engine TEXT NOT NULL DEFAULT 'gobgp',
    cache_ttl_seconds INTEGER NOT NULL DEFAULT 30,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    max_filter_routes_ipv4 INTEGER NOT NULL DEFAULT 50,
    max_filter_routes_ipv6 INTEGER NOT NULL DEFAULT 50,
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
    rr_node_ids TEXT NOT NULL DEFAULT '["all"]',
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
