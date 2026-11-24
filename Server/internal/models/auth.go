// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package models

import "time"

// AccessMode controls whether the Looking Glass requires login or is open to the public.
type AccessMode string

const (
	AccessModeAuthRequired AccessMode = "auth_required"
	AccessModePublic       AccessMode = "public"
)

// SystemSettings holds runtime-configurable access control and system settings stored in MySQL/MariaDB or SQLite.
type SystemSettings struct {
	AccessMode         AccessMode    `json:"access_mode"`
	AdminSecretSlug    string        `json:"admin_secret_slug,omitempty"` // Secret URL slug for admin console (never exposed to public bootstrap)
	PublicAllowedViews []RouteViewID `json:"public_allowed_views"`
	DefaultRRNode      string        `json:"default_rr_node"`
	DefaultEngine      string        `json:"default_engine"`
	CacheTTLSeconds    int           `json:"cache_ttl_seconds"`
	RateLimitPerMinute int           `json:"rate_limit_per_minute"`
	MaxFilterRoutesV4  int           `json:"max_filter_routes_ipv4"` // Max IPv4 routes returned for AS-Path / Community queries (default 50, range 1..5000)
	MaxFilterRoutesV6  int           `json:"max_filter_routes_ipv6"` // Max IPv6 routes returned for AS-Path / Community queries (default 50, range 1..5000)
	OrganizationName   string        `json:"organization_name"`
	FaviconIcon        string        `json:"favicon_icon"` // Custom browser tab favicon (base64 Data URL; empty = built-in default)
	PortalLogo         string        `json:"portal_logo"`  // Custom Public Portal header logo (base64 Data URL; empty = default BGP badge)
	PrimaryASN         uint32        `json:"primary_asn"`
	DatacenterCode     string        `json:"datacenter_code"`
	AllowRawOutput     bool          `json:"allow_raw_output"`
	UpdatedAt          time.Time     `json:"updated_at"`
}

// UserAccount represents an internal NOC user, Administrator, or Per-Customer Account.
type UserAccount struct {
	ID                 string        `json:"id"`
	Username           string        `json:"username"`
	PasswordHash       string        `json:"password_hash,omitempty"`
	DisplayName        string        `json:"display_name"`
	Company            string        `json:"company"`
	CustomerASN        uint32        `json:"customer_asn,omitempty"`
	Role               string        `json:"role"` // "admin", "noc", "customer"
	AllowedViews       []RouteViewID `json:"allowed_views"`
	RateLimitPerMinute int           `json:"rate_limit_per_minute"`
	Enabled            bool          `json:"enabled"`
	MustChangePassword bool          `json:"must_change_password"`
	Notes              string        `json:"notes,omitempty"`
	CreatedAt          time.Time     `json:"created_at"`
	LastLoginAt        *time.Time    `json:"last_login_at,omitempty"`
}

// LoginLockEntry describes a brute-force tracked or locked client IP / (IP + Username) pair for Admin Console management.
type LoginLockEntry struct {
	Key              string     `json:"key"`               // e.g. "ip:203.0.113.10" or "pair:203.0.113.10|admin"
	Type             string     `json:"type"`              // "ip" or "ip+user"
	Value            string     `json:"value"`             // Display label, e.g. "203.0.113.10" or "admin @ 203.0.113.10"
	Failures         int        `json:"failures"`
	MaxFailures      int        `json:"max_failures"`
	Locked           bool       `json:"locked"`
	RemainingSeconds int        `json:"remaining_seconds"`
	LastAttempt      time.Time  `json:"last_attempt"`
	LockedUntil      *time.Time `json:"locked_until,omitempty"`
}

// AuditLogEntry records queries and administrative changes.
type AuditLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Username   string    `json:"username"`
	ClientIP   string    `json:"client_ip"`
	Action     string    `json:"action"`
	QueryType  string    `json:"query_type,omitempty"`
	Target     string    `json:"target,omitempty"`
	Views      string    `json:"views,omitempty"`
	RRNode     string    `json:"rr_node,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
}
