// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { BootstrapResponse, POPGroup, RouteViewMeta, RRNodeConfig } from '../types';

export function getCurrentEntrySlug(): string {
  const hash = window.location.hash.replace(/^#\/?/, '').trim();
  if (hash) return hash;
  return window.location.pathname.replace(/^\/+|\/+$/g, '').trim();
}

export function computeConfiguredPOPGroups(boot: BootstrapResponse | null): POPGroup[] {
  if (!boot) return [];
  const map = new Map<string, POPGroup>();
  for (const p of boot.pops || []) {
    if (p.id?.trim()) {
      map.set(p.id.trim().toUpperCase(), {
        id: p.id.trim(),
        name: p.name?.trim() || p.id.trim(),
        description: p.description || '',
        sort_order: p.sort_order || 10,
      });
    }
  }
  for (const n of boot.rr_nodes || []) {
    const loc = n.location?.trim();
    if (loc && !map.has(loc.toUpperCase())) {
      map.set(loc.toUpperCase(), {
        id: loc,
        name: loc,
        description: '',
        sort_order: 99,
      });
    }
  }
  return Array.from(map.values());
}

export function computeActivePOPGroups(
  boot: BootstrapResponse | null,
  configuredPOPGroups: POPGroup[]
): POPGroup[] {
  if (!boot) return [];
  const enabledLocs = new Set<string>();
  for (const n of boot.rr_nodes || []) {
    if (n.enabled && n.location?.trim()) {
      enabledLocs.add(n.location.trim().toUpperCase());
    }
  }
  if (enabledLocs.size > 0) {
    const active = configuredPOPGroups.filter((p) => enabledLocs.has(p.id.toUpperCase()));
    if (active.length > 0) return active;
  }
  return configuredPOPGroups;
}

export function isViewBoundToRR(v: RouteViewMeta, rr: RRNodeConfig): boolean {
  const ids = v.rr_node_ids || [];
  if (ids.length > 0) {
    return ids.some((id) => id.toLowerCase() === 'all' || id === rr.id);
  }
  const vPop = (v.pop || '').trim().toLowerCase();
  if (vPop === 'none') return false;
  if (!vPop || vPop === 'all') return true;
  return vPop === (rr.location || '').trim().toLowerCase();
}

export function computeVisiblePermittedViews(
  boot: BootstrapResponse | null,
  selectedPOP: string
): RouteViewMeta[] {
  if (!boot) return [];
  const allPermitted = boot.permitted_views || [];
  if (!selectedPOP) return allPermitted;
  const targetPop = selectedPOP.trim().toLowerCase();
  const popRRs = (boot.rr_nodes || []).filter(
    (n) => n.enabled && (n.location || '').trim().toLowerCase() === targetPop
  );
  if (popRRs.length === 0) {
    return [];
  }
  return allPermitted.filter((v) => popRRs.some((rr) => isViewBoundToRR(v, rr)));
}
