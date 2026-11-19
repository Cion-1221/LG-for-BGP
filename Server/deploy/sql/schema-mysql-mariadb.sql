-- ==============================================================================
-- LG-for-BGP Relational Database Schema for MySQL 8.4+ / 9.x & MariaDB 11.x
-- Compatible with Debian 13 (Trixie) & Ubuntu 24.04 LTS (Noble) or higher
--
-- IMPORTANT ARCHITECTURE NOTE:
--   - All BGP routing tables and routes are stored EXCLUSIVELY in the RR's
--     in-memory RIBs (GoBGP Adj-RIB-In / BIRD 2 Tables / FRR Views).
--   - MySQL / MariaDB ONLY stores User Accounts, System Settings, PoP Groups,
--     VRF definitions, RR Node connection configs, and Audit Logs.
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS lg_for_bgp
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'lg_user'@'127.0.0.1' IDENTIFIED BY 'ChangeMe_StrongDBPass_2026!';
CREATE USER IF NOT EXISTS 'lg_user'@'localhost' IDENTIFIED BY 'ChangeMe_StrongDBPass_2026!';
GRANT ALL PRIVILEGES ON lg_for_bgp.* TO 'lg_user'@'127.0.0.1';
GRANT ALL PRIVILEGES ON lg_for_bgp.* TO 'lg_user'@'localhost';
FLUSH PRIVILEGES;

USE lg_for_bgp;

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
    rr_node_ids JSON NOT NULL,
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
