// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { POPGroup, RouteViewID, RouteViewMeta, RRNodeConfig } from './topology';

export type ThemeMode = 'light' | 'dark' | 'system';
export type AdminSectionID = 'settings' | 'views' | 'rr' | 'users' | 'logs';

export interface SystemSettings {
  access_mode: 'auth_required' | 'public';
  admin_secret_slug?: string;
  public_allowed_views: RouteViewID[];
  default_rr_node: string;
  default_engine: string;
  cache_ttl_seconds: number;
  rate_limit_per_minute: number;
  max_filter_routes_ipv4?: number;
  max_filter_routes_ipv6?: number;
  organization_name: string;
  favicon_icon?: string;
  portal_logo?: string;
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

export interface UserFormState {
  id?: string;
  username: string;
  password: string;
  display_name: string;
  company: string;
  customer_asn: number;
  role: 'admin' | 'noc' | 'customer';
  allowed_views: RouteViewID[];
  rate_limit_per_minute: number;
  enabled: boolean;
  must_change_password: boolean;
  notes: string;
}

export interface LoginLockEntry {
  key: string;
  type: 'ip' | 'ip+user' | string;
  value: string;
  failures: number;
  max_failures: number;
  locked: boolean;
  remaining_seconds: number;
  last_attempt: string;
  locked_until?: string;
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

export interface BootstrapResponse {
  settings: SystemSettings;
  current_user: UserAccount | null;
  session_invalidated?: boolean;
  admin_entry_verified: boolean;
  permitted_views: RouteViewMeta[];
  all_views: RouteViewMeta[];
  pops?: POPGroup[];
  rr_nodes: RRNodeConfig[];
}
