// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { BGPNeighborSummary, LookupResponse, RouteViewID, RRNodeConfig } from '../types';
import { request } from './client';

export const bgpApi = {
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
};
