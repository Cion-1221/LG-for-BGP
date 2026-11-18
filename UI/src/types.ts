export type RouteViewID = string;

export interface RouteViewMeta {
  id: RouteViewID;
  name: string;
  vrf_name: string;
  type: 'gobgp' | 'bird2' | 'frr' | string;
  pop?: string;
  short_name: string;
  junos_context_type: string;
  junos_context_name: string;
  junos_table: string;
  juniper_source_ipv4: string;
  juniper_source_ipv6: string;
  bird_table_v4: string;
  bird_table_v6: string;
  frr_view_name: string;
  description: string;
  badge_color: string;
}

export interface POPGroup {
  id: string;
  name: string;
  description: string;
  sort_order: number;
}

export interface RRNodeConfig {
  id: string;
  name: string;
  location: string;
  engine_type: string;
  loopback_ip: string;
  endpoint: string;
  role: string;
  enabled: boolean;
  healthy: boolean;
  last_checked: string;
}

export interface ASHop {
  asn: number;
  name: string;
  tier?: string;
}

export interface CommunityItem {
  raw: string;
  label: string;
  category: string;
}

export interface BGPRoutePath {
  path_id: number;
  prefix: string;
  address_family: string;
  best: boolean;
  next_hop: string;
  next_hop_isp: string;
  as_path: ASHop[];
  as_path_string: string;
  origin: string;
  local_pref: number;
  med: number;
  communities: CommunityItem[];
  ext_communities: string[];
  peer_ip: string;
  origin_asn: number;
  origin_name: string;
  rpki_status: string;
  age: string;
  validation_note: string;
}

export interface ViewQueryResult {
  view: RouteViewMeta;
  rr_node_id: string;
  rr_node_name: string;
  engine_type: string;
  query_target: string;
  matched_prefix: string;
  total_paths: number;
  paths: BGPRoutePath[];
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

export interface SystemSettings {
  access_mode: 'auth_required' | 'public';
  admin_secret_slug?: string;
  public_allowed_views: RouteViewID[];
  default_rr_node: string;
  default_engine: string;
  cache_ttl_seconds: number;
  rate_limit_per_minute: number;
  organization_name: string;
  primary_asn: number;
  datacenter_code: string;
  allow_raw_output: boolean;
  updated_at: string;
}

export interface UserAccount {
  id: string;
  username: string;
  display_name: string;
  company: string;
  customer_asn?: number;
  role: 'admin' | 'noc' | 'customer';
  allowed_views: RouteViewID[];
  rate_limit_per_minute: number;
  enabled: boolean;
  must_change_password?: boolean;
  notes?: string;
  created_at: string;
  last_login_at?: string;
}

export interface CommunityDictEntry {
  community: string;
  label: string;
  category: string;
  description: string;
}

export interface BGPNeighborSummary {
  view_id: RouteViewID;
  view_name: string;
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

export interface AuditLogEntry {
  timestamp: string;
  username: string;
  client_ip: string;
  action: string;
  query_type?: string;
  target?: string;
  views?: string;
  rr_node?: string;
  duration_ms?: number;
}
