// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
export type RouteViewID = string;

export interface RouteViewMeta {
  id: RouteViewID;
  name: string;
  vrf_name: string;
  type: 'auto' | 'gobgp' | 'bird2' | 'frr' | string;
  pop?: string;
  rr_node_ids?: string[];
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
  agent_token?: string;
  role: string;
  enabled: boolean;
  healthy: boolean;
  last_checked: string;
}
