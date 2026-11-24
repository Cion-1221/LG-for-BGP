// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { RouteViewID, RouteViewMeta } from './topology';

export type QueryType = 'prefix' | 'aspath' | 'community';

export interface ViewQueryResult {
  view: RouteViewMeta;
  rr_node_id: string;
  rr_node_name: string;
  engine_type: string;
  query_target: string;
  matched_prefix: string;
  total_paths: number;
  raw_output: string;
  query_time_ms: number;
  cached: boolean;
}

export interface LookupResponse {
  query_type: string;
  target: string;
  rr_node_used: string;
  engine_used: string;
  timestamp: string;
  results: ViewQueryResult[];
}

export interface BGPNeighborSummary {
  pop: string;
  rr_node_id: string;
  rr_node_name: string;
  engine_type: string;
  view_id: RouteViewID;
  view_name: string;
  vrf_name: string;
  junos_context: string;
  neighbor_ip: string;
  peer_asn: number;
  session_state: string;
  uptime: string;
  add_path_rx: boolean;
  next_hop_unchanged: boolean;
  prefixes_ipv4: number;
  prefixes_ipv6: number;
  updates_received: number;
}
