// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import {
  AuditLogEntry,
  BGPNeighborSummary,
  LoginLockEntry,
  LookupResponse,
  POPGroup,
  RouteViewID,
  RouteViewMeta,
  RRNodeConfig,
  SystemSettings,
  UserAccount,
} from './types';

const API_BASE =
  (import.meta as unknown as { env?: { VITE_API_BASE_URL?: string } }).env?.VITE_API_BASE_URL ||
  (window as unknown as { LG_API_BASE_URL?: string }).LG_API_BASE_URL ||
  '';

export function getToken(): string | null {
  return localStorage.getItem('lg_for_bgp_token');
}

export function setToken(token: string | null) {
  if (token) {
    localStorage.setItem('lg_for_bgp_token', token);
  } else {
    localStorage.removeItem('lg_for_bgp_token');
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== '/api/v1/auth/login') {
    setToken(null);
  }
  if (!res.ok) {
    throw new Error(data.error || `HTTP Error ${res.status}`);
  }
  return data as T;
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

export const api = {
  bootstrap: async (entryPath?: string) => {
    const data = await request<BootstrapResponse>(
      `/api/v1/bootstrap${entryPath ? `?entry=${encodeURIComponent(entryPath)}` : ''}`
    );
    if (data.session_invalidated || (getToken() && !data.current_user)) {
      setToken(null);
    }
    return data;
  },
  login: (username: string, password: string) =>
    request<{ token: string; user: UserAccount }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  changePassword: (current_password: string, new_password: string) =>
    request<{ token: string; user: UserAccount }>('/api/v1/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    }),
  lookupBGP: (payload: {
    query_type: string;
    target: string;
    views: RouteViewID[];
    pop?: string;
    rr_node_id: string;
    engine: string;
  }) =>
    request<LookupResponse>('/api/v1/bgp/lookup', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getSummary: () =>
    request<{ rr_nodes: RRNodeConfig[]; neighbors: BGPNeighborSummary[]; timestamp: string }>(
      '/api/v1/bgp/summary'
    ),
  updateSettings: (settings: SystemSettings) =>
    request<SystemSettings>('/api/v1/admin/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    }),
  saveRouteView: (view: RouteViewMeta) =>
    request<RouteViewMeta[]>('/api/v1/admin/views', {
      method: 'POST',
      body: JSON.stringify(view),
    }),
  deleteRouteView: (id: string) =>
    request<RouteViewMeta[]>(`/api/v1/admin/views?id=${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  savePOP: (pop: POPGroup) =>
    request<POPGroup[]>('/api/v1/admin/pops', {
      method: 'POST',
      body: JSON.stringify(pop),
    }),
  deletePOP: (id: string) =>
    request<POPGroup[]>(`/api/v1/admin/pops?id=${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  saveRRNode: (node: RRNodeConfig) =>
    request<RRNodeConfig[]>('/api/v1/admin/rr-nodes', {
      method: 'POST',
      body: JSON.stringify(node),
    }),
  deleteRRNode: (id: string) =>
    request<RRNodeConfig[]>(`/api/v1/admin/rr-nodes?id=${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  probeRRNode: (id: string) =>
    request<{
      id: string;
      reachable: boolean;
      latency_ms: number;
      message: string;
      rr_nodes: RRNodeConfig[];
    }>('/api/v1/admin/rr-nodes/probe', {
      method: 'POST',
      body: JSON.stringify({ id }),
    }),
  getUsers: () => request<UserAccount[]>('/api/v1/admin/users'),
  saveUser: (user: Partial<UserAccount> & { password?: string }) =>
    request<UserAccount>('/api/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify(user),
    }),
  deleteUser: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/users?id=${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  getAuditLogs: () => request<AuditLogEntry[]>('/api/v1/admin/audit-logs'),
  getLoginLocks: () => request<LoginLockEntry[]>('/api/v1/admin/security/locks'),
  unbanLoginLock: (key: string) =>
    request<{ removed: number; locks: LoginLockEntry[] }>(
      `/api/v1/admin/security/locks?key=${encodeURIComponent(key)}`,
      { method: 'DELETE' }
    ),
  clearCache: () =>
    request<{ status: string }>('/api/v1/admin/cache/clear', {
      method: 'POST',
    }),
};
