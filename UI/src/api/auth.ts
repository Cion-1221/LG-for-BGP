// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { BootstrapResponse, UserAccount } from '../types';
import { getToken, request, setToken } from './client';

export const authApi = {
  bootstrap: async (entryPath?: string): Promise<BootstrapResponse> => {
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
};
