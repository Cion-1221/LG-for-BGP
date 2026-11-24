// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { adminApi } from './admin';
import { authApi } from './auth';
import { bgpApi } from './bgp';

export { getToken, setToken } from './client';

export const api = {
  ...authApi,
  ...bgpApi,
  ...adminApi,
};
