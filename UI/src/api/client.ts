// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
const API_BASE =
  (import.meta as unknown as { env?: { VITE_API_BASE_URL?: string } }).env?.VITE_API_BASE_URL ||
  (window as unknown as { LG_API_BASE_URL?: string }).LG_API_BASE_URL ||
  '';

export function getToken(): string | null {
  return localStorage.getItem('lg_for_bgp_token');
}

export function setToken(token: string | null): void {
  if (token) {
    localStorage.setItem('lg_for_bgp_token', token);
  } else {
    localStorage.removeItem('lg_for_bgp_token');
  }
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
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
