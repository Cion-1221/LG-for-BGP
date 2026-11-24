// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package models

import "time"

// ViewQueryResult holds the pure-CLI text query result for one specific RouteView.
type ViewQueryResult struct {
	View        RouteViewMeta `json:"view"`
	RRNodeID    string        `json:"rr_node_id"`
	RRNodeName  string        `json:"rr_node_name"`
	EngineType  string        `json:"engine_type"`
	QueryTarget string        `json:"query_target"`
	MatchedNet  string        `json:"matched_prefix"`
	TotalPaths  int           `json:"total_paths"`
	RawOutput   string        `json:"raw_output"`
	QueryTimeMs int64         `json:"query_time_ms"`
	Cached      bool          `json:"cached"`
}

// LookupRequest represents a Prefix / AS-Path / Community query from the UI.
type LookupRequest struct {
	QueryType string        `json:"query_type"` // "prefix", "aspath", "community"
	Target    string        `json:"target"`
	Views     []RouteViewID `json:"views"`
	POP       string        `json:"pop,omitempty"` // Selected POP location (e.g. "HKG-POP-01" or "all")
	RRNodeID  string        `json:"rr_node_id"`    // "auto", "rr-01", "rr-02"
	Engine    string        `json:"engine"`        // "auto", "gobgp", "bird2", "frr"
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

// BGPNeighborSummary represents the live BGP session state between an RR and a router instance for a specific VRF.
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
