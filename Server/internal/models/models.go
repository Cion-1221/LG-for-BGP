package models

import "time"

// RouteViewID identifies a logical BGP routing table / instance configured in the system.
type RouteViewID string

const (
	ViewLogicalSystemOpt RouteViewID = "lsys_opt"      // Example: Juniper logical-systems (Optimized Routing)
	ViewVRFGlobalDIA     RouteViewID = "vrf_dia"       // Example: Juniper routing-instances (Global DIA Blend)
	ViewVRFTransitA      RouteViewID = "vrf_transit_a" // Example: Juniper routing-instances (Upstream Transit A)
	ViewVRFTransitB      RouteViewID = "vrf_transit_b" // Example: Juniper routing-instances (Upstream Transit B)
)

// RouteViewMeta describes a VRF / RIB configuration entry managed in the Web Admin Console.
// A VRF can be bound to 1 RR node, multiple RR nodes, or all RR nodes (RRNodeIDs = ["all"]).
// Each RR node belongs strictly to 1 PoP (RRNodeConfig.Location).
// Note: Only this VRF metadata is stored in configuration;
// all actual BGP routes reside strictly in each RR's in-memory VRF RIB.
type RouteViewMeta struct {
	ID                RouteViewID `json:"id"`
	Name              string      `json:"name"`                  // Display Name shown on the Frontend UI
	VRFName           string      `json:"vrf_name"`              // Underlying VRF / RIB table name on the RR (e.g. "VRF-DIA")
	Type              string      `json:"type"`                  // Optional engine hint: "auto", "gobgp", "bird2", or "frr" (RR's own engine_type takes precedence)
	POP               string      `json:"pop"`                   // Legacy PoP scope kept for backward migration; RRNodeIDs is the primary binding
	RRNodeIDs         []string    `json:"rr_node_ids"`           // Bound RR node IDs: ["all"] for all RRs, or specific RR IDs (e.g. ["rr-01", "rr-02"])
	ShortName         string      `json:"short_name"`            // Short badge label (defaults to VRFName)
	JunosContextType  string      `json:"junos_context_type"`
	JunosContextName  string      `json:"junos_context_name"`
	JunosTable        string      `json:"junos_table"`
	JuniperSourceIPv4 string      `json:"juniper_source_ipv4"`
	JuniperSourceIPv6 string      `json:"juniper_source_ipv6"`
	BirdTableV4       string      `json:"bird_table_v4"`
	BirdTableV6       string      `json:"bird_table_v6"`
	FrrViewName       string      `json:"frr_view_name"`
	Description       string      `json:"description"`
	BadgeColor        string      `json:"badge_color"`
}

// POPGroup represents a Point of Presence (PoP) group that RR nodes are assigned to.
type POPGroup struct {
	ID          string `json:"id"`          // Unique PoP code/slug (e.g. "HKG-POP-01", "TYO-POP-01")
	Name        string `json:"name"`        // Display name shown on PoP tabs (e.g. "Hong Kong POP", "Tokyo POP")
	Description string `json:"description"` // Optional description or datacenter facility note
	SortOrder   int    `json:"sort_order"`
}

// RRNodeConfig represents a Route Reflector / Collector node (e.g., RR-01, RR-02).
// Every RR node belongs strictly to ONE PoP (Location).
type RRNodeConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Location    string `json:"location"`              // Bound PoP Group ID (strictly 1 PoP per RR)
	EngineType  string `json:"engine_type"`           // "gobgp", "bird2", "frr"
	LoopbackIP  string `json:"loopback_ip"`
	Endpoint    string `json:"endpoint"`              // GoBGP host:port, local socket path, or remote lg-agent URL (http(s)://host:port)
	AgentToken  string `json:"agent_token,omitempty"` // Optional Bearer token for remote lg-agent (stripped from public bootstrap)
	Role        string `json:"role"`                  // "primary" or "backup"
	Enabled     bool   `json:"enabled"`
	Healthy     bool   `json:"healthy"`
	LastChecked string `json:"last_checked"`
}

// ASHop represents a single ASN in an AS_PATH with resolved organization name.
type ASHop struct {
	ASN  uint32 `json:"asn"`
	Name string `json:"name"`
	Tier string `json:"tier,omitempty"`
}

// CommunityItem represents a BGP Community (Standard, Extended, or Large) with translated meaning.
type CommunityItem struct {
	Raw      string `json:"raw"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

// BGPRoutePath represents a single BGP path received from the router via iBGP (Add-Path preserved).
// NextHop and all BGP attributes are preserved 100% unmodified as received.
type BGPRoutePath struct {
	PathID         uint32          `json:"path_id"`
	Prefix         string          `json:"prefix"`
	AddressFamily  string          `json:"address_family"`
	Best           bool            `json:"best"`
	NextHop        string          `json:"next_hop"`
	NextHopISP     string          `json:"next_hop_isp"`
	ASPath         []ASHop         `json:"as_path"`
	ASPathString   string          `json:"as_path_string"`
	Origin         string          `json:"origin"`
	LocalPref      uint32          `json:"local_pref"`
	MED            uint32          `json:"med"`
	Communities    []CommunityItem `json:"communities"`
	ExtCommunities []string        `json:"ext_communities"`
	PeerIP         string          `json:"peer_ip"`
	OriginASN      uint32          `json:"origin_asn"`
	OriginName     string          `json:"origin_name"`
	RPKIStatus     string          `json:"rpki_status"`
	Age            string          `json:"age"`
	ValidationNote string          `json:"validation_note"`
}

// ViewQueryResult holds the query result for one specific RouteView.
type ViewQueryResult struct {
	View        RouteViewMeta  `json:"view"`
	RRNodeID    string         `json:"rr_node_id"`
	RRNodeName  string         `json:"rr_node_name"`
	EngineType  string         `json:"engine_type"`
	QueryTarget string         `json:"query_target"`
	MatchedNet  string         `json:"matched_prefix"`
	TotalPaths  int            `json:"total_paths"`
	Paths       []BGPRoutePath `json:"paths"`
	RawOutput   string         `json:"raw_output"`
	QueryTimeMs int64          `json:"query_time_ms"`
	Cached      bool           `json:"cached"`
}

// LookupRequest represents a Prefix / AS-Path / Community query from the UI.
type LookupRequest struct {
	QueryType string        `json:"query_type"` // "prefix", "aspath", "community"
	Target    string        `json:"target"`
	Views     []RouteViewID `json:"views"`
	POP       string        `json:"pop,omitempty"` // Selected POP location (e.g. "HKG-POP-01" or "all")
	RRNodeID  string        `json:"rr_node_id"`    // "auto", "rr-01", "rr-02"
	Engine    string        `json:"engine"`        // "gobgp", "bird2", "frr"
}

// LookupResponse returns results across all requested RouteViews.
type LookupResponse struct {
	QueryType  string            `json:"query_type"`
	Target     string            `json:"target"`
	RRNodeUsed string            `json:"rr_node_used"`
	EngineUsed string            `json:"engine_used"`
	Timestamp  time.Time         `json:"timestamp"`
	Results    []ViewQueryResult `json:"results"`
}

// BGPNeighborSummary represents the BGP session state between an RR and a router instance for a specific VRF.
type BGPNeighborSummary struct {
	POP              string      `json:"pop"`
	RRNodeID         string      `json:"rr_node_id"`
	RRNodeName       string      `json:"rr_node_name"`
	EngineType       string      `json:"engine_type"`
	ViewID           RouteViewID `json:"view_id"`
	ViewName         string      `json:"view_name"`
	VRFName          string      `json:"vrf_name"`
	JunosContext     string      `json:"junos_context"`
	NeighborIP       string      `json:"neighbor_ip"`
	PeerASN          uint32      `json:"peer_asn"`
	SessionState     string      `json:"session_state"`
	Uptime           string      `json:"uptime"`
	AddPathRx        bool        `json:"add_path_rx"`
	NextHopUnchanged bool        `json:"next_hop_unchanged"`
	PrefixesIPv4     int         `json:"prefixes_ipv4"`
	PrefixesIPv6     int         `json:"prefixes_ipv6"`
	UpdatesReceived  int64       `json:"updates_received"`
}

// LoginLockEntry describes a brute-force tracked or locked client IP / username for Admin Console management.
type LoginLockEntry struct {
	Key              string     `json:"key"`               // e.g. "ip:203.0.113.10" or "user:admin"
	Type             string     `json:"type"`              // "ip" or "username"
	Value            string     `json:"value"`             // Raw IP or username
	Failures         int        `json:"failures"`
	MaxFailures      int        `json:"max_failures"`
	Locked           bool       `json:"locked"`
	RemainingSeconds int        `json:"remaining_seconds"`
	LastAttempt      time.Time  `json:"last_attempt"`
	LockedUntil      *time.Time `json:"locked_until,omitempty"`
}

// AccessMode controls whether the Looking Glass requires login or is open to the public.
type AccessMode string

const (
	AccessModeAuthRequired AccessMode = "auth_required"
	AccessModePublic       AccessMode = "public"
)

// SystemSettings holds runtime-configurable access control and system settings stored in MySQL/MariaDB.
type SystemSettings struct {
	AccessMode         AccessMode    `json:"access_mode"`
	AdminSecretSlug    string        `json:"admin_secret_slug,omitempty"` // Secret URL slug for admin console (never exposed to public bootstrap)
	PublicAllowedViews []RouteViewID `json:"public_allowed_views"`
	DefaultRRNode      string        `json:"default_rr_node"`
	DefaultEngine      string        `json:"default_engine"`
	CacheTTLSeconds    int           `json:"cache_ttl_seconds"`
	RateLimitPerMinute int           `json:"rate_limit_per_minute"`
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
