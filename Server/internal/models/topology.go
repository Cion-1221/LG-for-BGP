// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package models

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
	Name              string      `json:"name"`        // Display Name shown on the Frontend UI
	VRFName           string      `json:"vrf_name"`    // Underlying VRF / RIB table name on the RR (e.g. "VRF-DIA")
	Type              string      `json:"type"`        // Optional engine hint: "auto", "gobgp", "bird2", or "frr"
	POP               string      `json:"pop"`         // Derived PoP scope kept for compatibility; RRNodeIDs is primary
	RRNodeIDs         []string    `json:"rr_node_ids"` // Bound RR node IDs: ["all"] or specific RR IDs
	ShortName         string      `json:"short_name"`
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
	Name        string `json:"name"`        // Display name shown on PoP tabs (e.g. "Hong Kong POP")
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
	Endpoint    string `json:"endpoint"`              // GoBGP host:port, local socket path, or remote lg-agent URL
	AgentToken  string `json:"agent_token,omitempty"` // Optional Bearer token for remote lg-agent (stripped from public bootstrap)
	Role        string `json:"role"`                  // "primary" or "backup"
	Enabled     bool   `json:"enabled"`
	Healthy     bool   `json:"healthy"`
	LastChecked string `json:"last_checked"`
}
