// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import {
  AuditLogEntry,
  LoginLockEntry,
  POPGroup,
  RouteViewMeta,
  RRNodeConfig,
  SystemSettings,
  UserAccount,
} from '../types';
import { request } from './client';

export const adminApi = {
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
