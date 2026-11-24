// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useMemo, useState } from 'react';
import { api } from '../../../api';
import { ThemeTokens } from '../../../hooks/useTheme';
import { BGPNeighborSummary, BootstrapResponse, POPGroup, RRNodeConfig } from '../../../types';

interface PopAndRrSectionProps {
  boot: BootstrapResponse;
  ui: ThemeTokens;
  configuredPOPGroups: POPGroup[];
  popNameByID: Map<string, string>;
  neighbors: BGPNeighborSummary[];
  neighborsLoading: boolean;
  neighborsUpdatedAt: string;
  onRefreshNeighbors: () => Promise<void>;
  setAdminMsg: (msg: string) => void;
  reloadAll: () => Promise<void>;
}

export const PopAndRrSection: React.FC<PopAndRrSectionProps> = ({
  boot,
  ui,
  configuredPOPGroups,
  popNameByID,
  neighbors,
  neighborsLoading,
  neighborsUpdatedAt,
  onRefreshNeighbors,
  setAdminMsg,
  reloadAll,
}) => {
  const [editingPOP, setEditingPOP] = useState<POPGroup>({
    id: '',
    name: '',
    description: '',
    sort_order: 10,
  });

  const [editingRR, setEditingRR] = useState<RRNodeConfig>({
    id: '',
    name: '',
    location: '',
    engine_type: 'gobgp',
    loopback_ip: '',
    endpoint: '127.0.0.1:50051',
    agent_token: '',
    role: 'primary',
    enabled: true,
    healthy: true,
    last_checked: '',
  });

  const rrsByPOP = useMemo(() => {
    const map = new Map<string, RRNodeConfig[]>();
    for (const n of boot.rr_nodes || []) {
      const popKey = n.location?.trim() || boot.settings.datacenter_code || 'DEFAULT-POP';
      const list = map.get(popKey) || [];
      list.push(n);
      map.set(popKey, list);
    }
    return map;
  }, [boot.rr_nodes, boot.settings.datacenter_code]);

  return (
    <div className="space-y-6 text-xs">
      {/* STEP 1: DEFINE POP GROUPS */}
      <div className={`${ui.bgCard} border rounded-2xl p-6 space-y-5`}>
        <div>
          <h2 className={`text-base font-bold ${ui.textPrimary} mb-1`}>
            Step 1: PoP Group Management (Define PoPs First)
          </h2>
          <p className={ui.textSecondary}>
            Define your Points of Presence (PoPs) as groups here first (e.g.,{' '}
            <code className="text-sky-700 dark:text-sky-400">HKG-POP-01</code>,{' '}
            <code className="text-sky-700 dark:text-sky-400">TYO-POP-01</code>,{' '}
            <code className="text-sky-700 dark:text-sky-400">SGP-POP-01</code>). If 2 or more PoPs
            are active, the Public Looking Glass automatically displays PoP tabs above the query
            bar.
          </p>
        </div>

        {configuredPOPGroups.length === 0 ? (
          <div className={`p-4 rounded-xl border text-center ${ui.bgSubCard} ${ui.textSecondary}`}>
            No PoP groups defined yet. Create your first PoP group below.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {configuredPOPGroups.map((pop) => (
              <div
                key={pop.id}
                className={`p-3.5 rounded-xl border flex flex-col justify-between gap-2 ${ui.bgSubCard}`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className={`font-bold text-sm ${ui.textPrimary}`}>{pop.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-sky-500/15 text-sky-700 dark:text-sky-400 border border-sky-500/30 font-mono font-semibold">
                      {pop.id}
                    </span>
                  </div>
                  {pop.description && (
                    <div className={`mt-1 ${ui.textSecondary}`}>{pop.description}</div>
                  )}
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-slate-200 dark:border-slate-800/60">
                  <button
                    type="button"
                    onClick={() => setEditingPOP(pop)}
                    className="text-sky-700 dark:text-sky-400 hover:underline font-medium"
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await api.deletePOP(pop.id);
                        setAdminMsg(`Deleted PoP group ${pop.id}`);
                        await reloadAll();
                      } catch (err: unknown) {
                        setAdminMsg(err instanceof Error ? err.message : 'Delete failed');
                      }
                    }}
                    className="text-rose-500 hover:underline font-medium ml-auto"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api.savePOP(editingPOP);
              setAdminMsg(`Saved PoP Group: ${editingPOP.name || editingPOP.id}`);
              setEditingPOP({ id: '', name: '', description: '', sort_order: 10 });
              await reloadAll();
            } catch (err: unknown) {
              setAdminMsg(err instanceof Error ? err.message : 'Save PoP failed');
            }
          }}
          className="grid grid-cols-1 md:grid-cols-4 gap-3.5 pt-4 border-t border-slate-200 dark:border-slate-800/70 items-end"
        >
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>PoP Code / ID *</label>
            <input
              type="text"
              required
              value={editingPOP.id}
              onChange={(e) => setEditingPOP({ ...editingPOP, id: e.target.value })}
              placeholder="e.g. HKG-POP-01"
              className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              PoP Display Name *
            </label>
            <input
              type="text"
              required
              value={editingPOP.name}
              onChange={(e) => setEditingPOP({ ...editingPOP, name: e.target.value })}
              placeholder="e.g. Hong Kong POP"
              className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              Description (Optional)
            </label>
            <input
              type="text"
              value={editingPOP.description}
              onChange={(e) => setEditingPOP({ ...editingPOP, description: e.target.value })}
              placeholder="e.g. Equinix HK1 / MEGA-i"
              className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
            />
          </div>
          <button
            type="submit"
            className="py-2 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition"
          >
            Save PoP Group
          </button>
        </form>
      </div>

      {/* STEP 2: ROUTE REFLECTOR (RR) NODES */}
      <div className={`${ui.bgCard} border rounded-2xl p-6 space-y-5`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className={`text-base font-bold ${ui.textPrimary} mb-1`}>
              Step 2: Route Reflector (RR) Collector Nodes (Assigned by PoP Group)
            </h2>
            <p className={ui.textSecondary}>
              Assign each RR node to a defined PoP Group and configure 1 or multiple RRs (
              <code className="text-sky-700 dark:text-sky-400">primary</code> +{' '}
              <code className="text-amber-700 dark:text-amber-400">backup</code>) per PoP.
            </p>
          </div>
          <button
            type="button"
            onClick={() =>
              setEditingRR({
                id: `rr-0${boot.rr_nodes.length + 1}`,
                name: `LG-RR0${boot.rr_nodes.length + 1}`,
                location:
                  configuredPOPGroups[0]?.id || boot.settings.datacenter_code || 'HKG-POP-01',
                engine_type: 'gobgp',
                loopback_ip: '127.0.0.1',
                endpoint: '127.0.0.1:50051',
                agent_token: '',
                role: boot.rr_nodes.length === 0 ? 'primary' : 'backup',
                enabled: true,
                healthy: true,
                last_checked: '',
              })
            }
            className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold shrink-0"
          >
            + New RR Node Form
          </button>
        </div>

        {boot.rr_nodes.length === 0 ? (
          <div
            className={`p-6 rounded-xl border text-center text-amber-700 dark:text-amber-400 ${ui.bgSubCard}`}
          >
            No Route Reflector (RR) node configured yet. Add at least 1 RR node below to enable BGP
            route queries.
          </div>
        ) : (
          <div className="space-y-4">
            {Array.from(rrsByPOP.entries()).map(([popCode, popNodes]) => (
              <div key={popCode} className={`p-4 rounded-xl border ${ui.bgSubCard} space-y-3`}>
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/70 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-md bg-sky-500/15 text-sky-700 dark:text-sky-400 border border-sky-500/30 font-mono font-bold">
                      PoP: {popNameByID.get(popCode.toUpperCase()) || popCode} ({popCode})
                    </span>
                    <span className={ui.textSecondary}>
                      ({popNodes.length} {popNodes.length === 1 ? 'RR Node' : 'RR Nodes'})
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                  {popNodes.map((n) => (
                    <div
                      key={n.id}
                      className={`p-4 rounded-xl border flex flex-col justify-between gap-3 ${
                        n.enabled ? ui.bgCard : `${ui.bgCard} opacity-60`
                      }`}
                    >
                      <div>
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className={`font-bold text-sm flex items-center gap-2 ${ui.textPrimary}`}>
                            <span>{n.name}</span>
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase ${
                                n.role === 'primary'
                                  ? 'bg-sky-500/20 text-sky-700 dark:text-sky-400 border border-sky-500/30'
                                  : 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-500/30'
                              }`}
                            >
                              {n.role}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                                n.enabled
                                  ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-400'
                                  : 'bg-rose-500/20 text-rose-500'
                              }`}
                            >
                              {n.enabled ? 'ENABLED' : 'DISABLED'}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-200/80 text-slate-700 dark:bg-slate-800 dark:text-slate-300 font-mono uppercase">
                              {n.engine_type === 'gobgp' ? 'GOBGP (gRPC)' : n.engine_type}
                            </span>
                          </div>
                        </div>
                        <div className="font-mono text-sky-700 dark:text-sky-400 mt-2">
                          Endpoint:{' '}
                          <span className="text-emerald-700 dark:text-emerald-400">
                            {n.endpoint}
                          </span>{' '}
                          · Loopback: {n.loopback_ip}
                        </div>
                        <div className={`font-mono mt-0.5 text-[11px] ${ui.textSecondary}`}>
                          ID: {n.id} · PoP: {n.location} · Status:{' '}
                          <span
                            className={
                              n.healthy
                                ? 'text-emerald-700 dark:text-emerald-400'
                                : 'text-amber-700 dark:text-amber-400'
                            }
                          >
                            {n.healthy ? 'Reachable' : 'Unverified'}
                          </span>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 pt-2.5 border-t border-slate-200 dark:border-slate-800/70">
                        <button
                          type="button"
                          onClick={async () => {
                            try {
                              const res = await api.probeRRNode(n.id);
                              setAdminMsg(
                                `[Probe ${n.name}] ${res.reachable ? 'REACHABLE' : 'FAILED'}: ${res.message}`
                              );
                              await reloadAll();
                            } catch (err: unknown) {
                              setAdminMsg(err instanceof Error ? err.message : 'Probe failed');
                            }
                          }}
                          className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30 font-medium"
                        >
                          Test Connection
                        </button>
                        <button
                          type="button"
                          onClick={() => setEditingRR({ ...n, agent_token: n.agent_token || '' })}
                          className="px-2.5 py-1 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-700 dark:text-sky-400 font-medium"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={async () => {
                            try {
                              await api.saveRRNode({ ...n, enabled: !n.enabled });
                              setAdminMsg(
                                `RR Node ${n.name} is now ${!n.enabled ? 'ENABLED' : 'DISABLED'}`
                              );
                              await reloadAll();
                            } catch (err: unknown) {
                              setAdminMsg(err instanceof Error ? err.message : 'Update failed');
                            }
                          }}
                          className="px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-700 dark:text-amber-400 font-medium"
                        >
                          {n.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          type="button"
                          onClick={async () => {
                            try {
                              await api.deleteRRNode(n.id);
                              setAdminMsg(`Deleted RR Node ${n.name}`);
                              await reloadAll();
                            } catch (err: unknown) {
                              setAdminMsg(err instanceof Error ? err.message : 'Delete failed');
                            }
                          }}
                          className="px-2.5 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-500 font-medium ml-auto"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              const targetPOP =
                editingRR.location.trim() ||
                configuredPOPGroups[0]?.id ||
                boot.settings.datacenter_code ||
                'CORE-POP-01';
              await api.saveRRNode({ ...editingRR, location: targetPOP });
              setAdminMsg(
                `Saved RR Node: ${editingRR.name} [PoP: ${targetPOP}] (${editingRR.endpoint})`
              );
              await reloadAll();
            } catch (err: unknown) {
              setAdminMsg(err instanceof Error ? err.message : 'Save failed');
            }
          }}
          className="pt-5 border-t border-slate-200 dark:border-slate-800/70 space-y-3.5"
        >
          <h3 className={`text-sm font-bold ${ui.textPrimary}`}>
            Add or Update Route Reflector (RR) Node
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                1. Select PoP Group *
              </label>
              {configuredPOPGroups.length > 0 ? (
                <select
                  value={editingRR.location || configuredPOPGroups[0].id}
                  onChange={(e) => setEditingRR({ ...editingRR, location: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
                >
                  {configuredPOPGroups.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.id})
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  required
                  value={editingRR.location}
                  onChange={(e) => setEditingRR({ ...editingRR, location: e.target.value })}
                  placeholder="Define a PoP in Step 1 above (e.g. HKG-POP-01)"
                  className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
                />
              )}
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                2. RR Node Name *
              </label>
              <input
                type="text"
                required
                value={editingRR.name}
                onChange={(e) => setEditingRR({ ...editingRR, name: e.target.value })}
                placeholder="e.g. LG-RR01"
                className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
              />
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                3. RR Engine Type *
              </label>
              <select
                value={editingRR.engine_type}
                onChange={(e) => {
                  const nextEngine = e.target.value;
                  let nextEndpoint = editingRR.endpoint;
                  if (
                    nextEngine === 'gobgp' &&
                    (!nextEndpoint ||
                      nextEndpoint.startsWith('/') ||
                      nextEndpoint.startsWith('http'))
                  ) {
                    nextEndpoint = '127.0.0.1:50051';
                  } else if (
                    nextEngine === 'bird2' &&
                    (!nextEndpoint ||
                      (nextEndpoint.includes(':') && !nextEndpoint.startsWith('http')))
                  ) {
                    nextEndpoint = '/run/bird/bird.ctl';
                  } else if (
                    nextEngine === 'frr' &&
                    (!nextEndpoint ||
                      (nextEndpoint.includes(':') && !nextEndpoint.startsWith('http')))
                  ) {
                    nextEndpoint = '/run/frr';
                  }
                  setEditingRR({
                    ...editingRR,
                    engine_type: nextEngine,
                    endpoint: nextEndpoint,
                  });
                }}
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              >
                <option value="gobgp">gobgp (GoBGP Native gRPC)</option>
                <option value="bird2">bird2 (BIRD 2 Socket or lg-agent)</option>
                <option value="frr">frr (FRR/VyOS vtysh or lg-agent)</option>
              </select>
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                4.{' '}
                {editingRR.engine_type === 'gobgp'
                  ? 'GoBGP gRPC Endpoint (host:port) *'
                  : editingRR.engine_type === 'bird2'
                    ? 'BIRD 2 Socket Path or lg-agent URL *'
                    : 'FRR Socket Dir or lg-agent URL *'}
              </label>
              <input
                type="text"
                required
                value={editingRR.endpoint}
                onChange={(e) => setEditingRR({ ...editingRR, endpoint: e.target.value })}
                placeholder={
                  editingRR.engine_type === 'gobgp'
                    ? 'e.g. 127.0.0.1:50051'
                    : editingRR.engine_type === 'bird2'
                      ? 'e.g. /run/bird/bird.ctl or http://10.0.0.2:9090'
                      : 'e.g. /run/frr or http://10.0.0.2:9090'
                }
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-3.5 items-end">
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                5. RR Loopback IP *
              </label>
              <input
                type="text"
                required
                value={editingRR.loopback_ip}
                onChange={(e) => setEditingRR({ ...editingRR, loopback_ip: e.target.value })}
                placeholder="e.g. 192.168.0.199"
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              />
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                6. Role in PoP *
              </label>
              <select
                value={editingRR.role || 'primary'}
                onChange={(e) => setEditingRR({ ...editingRR, role: e.target.value })}
                className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
              >
                <option value="primary">primary (Preferred RR in PoP)</option>
                <option value="backup">backup (Failover RR in PoP)</option>
              </select>
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                7. Node ID (Auto if blank)
              </label>
              <input
                type="text"
                value={editingRR.id}
                onChange={(e) => setEditingRR({ ...editingRR, id: e.target.value })}
                placeholder="e.g. rr-01"
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              />
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                8. lg-agent Token (Remote BIRD/FRR)
              </label>
              <input
                type="password"
                value={editingRR.agent_token || ''}
                onChange={(e) => setEditingRR({ ...editingRR, agent_token: e.target.value })}
                placeholder="Optional Bearer token"
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              />
            </div>
            <div className="flex items-center gap-3">
              <label className={`flex items-center gap-1.5 cursor-pointer shrink-0 ${ui.textPrimary}`}>
                <input
                  type="checkbox"
                  checked={editingRR.enabled !== false}
                  onChange={(e) => setEditingRR({ ...editingRR, enabled: e.target.checked })}
                />
                Enabled
              </label>
              <button
                type="submit"
                className="flex-1 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
              >
                Save RR Node
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* LIVE BGP NEIGHBOR SESSION SUMMARY */}
      <div className={`${ui.bgCard} border rounded-2xl p-6 overflow-x-auto`}>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div>
            <h3 className={`text-sm font-bold ${ui.textPrimary}`}>
              Live iBGP Neighbor Session Summary (Admin Only)
            </h3>
            <p className={`text-[11px] ${ui.textSecondary} mt-0.5`}>
              Queries live BGP neighbor sessions and negotiated capabilities per (PoP · RR Node ·
              Bound VRF) across GoBGP gRPC, BIRD 2, and FRR.
              {neighborsUpdatedAt ? ` Last refreshed: ${neighborsUpdatedAt}` : ''}
            </p>
          </div>
          <button
            type="button"
            disabled={neighborsLoading}
            onClick={onRefreshNeighbors}
            className={`px-3.5 py-1.5 rounded-lg border font-semibold transition disabled:opacity-50 ${ui.badgeSky}`}
          >
            {neighborsLoading ? 'Refreshing Peers...' : '↻ Refresh Peers'}
          </button>
        </div>
        <table className="w-full text-left text-xs">
          <thead>
            <tr className={`border-b border-slate-200 dark:border-slate-800/70 ${ui.textSecondary}`}>
              <th className="py-2.5 px-2.5">PoP</th>
              <th className="py-2.5 px-2.5">RR Node</th>
              <th className="py-2.5 px-2.5">Route View</th>
              <th className="py-2.5 px-2.5">VRF / Instance</th>
              <th className="py-2.5 px-2.5">Neighbor IP / AS</th>
              <th className="py-2.5 px-2.5">Session State</th>
              <th className="py-2.5 px-2.5">Add-Path RX</th>
              <th className="py-2.5 px-2.5">IPv4 / IPv6 Pfx</th>
              <th className="py-2.5 px-2.5">Updates RX</th>
              <th className="py-2.5 px-2.5">Uptime</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono">
            {neighbors.length === 0 ? (
              <tr>
                <td colSpan={10} className={`py-4 text-center font-sans ${ui.textSecondary}`}>
                  No bound RR / VRF neighbor sessions configured.
                </td>
              </tr>
            ) : (
              neighbors.map((n, idx) => {
                const isEst = n.session_state === 'Established';
                const isIdle =
                  n.session_state === 'No Peer / Idle' || n.session_state === 'No Bound RR';
                return (
                  <tr
                    key={`${n.rr_node_id || 'unbound'}::${n.view_id}::${n.neighbor_ip || 'none'}::${idx}`}
                  >
                    <td className="py-2.5 px-2.5">
                      <span
                        className={`px-2 py-0.5 rounded border text-[10px] font-semibold ${ui.badgeSky}`}
                      >
                        {n.pop ? popNameByID.get(n.pop.toUpperCase()) || n.pop : '-'}
                      </span>
                    </td>
                    <td className={`py-2.5 px-2.5 ${ui.textPrimary}`}>
                      <span className="font-semibold">{n.rr_node_name || '-'}</span>
                      {n.engine_type && (
                        <span className={`ml-1.5 text-[10px] uppercase ${ui.textSecondary}`}>
                          [{n.engine_type}]
                        </span>
                      )}
                    </td>
                    <td className={`py-2.5 px-2.5 font-sans font-semibold ${ui.textPrimary}`}>
                      {n.view_name}
                    </td>
                    <td className="py-2.5 px-2.5 text-sky-700 dark:text-sky-400">{n.vrf_name}</td>
                    <td className={`py-2.5 px-2.5 ${ui.textSecondary}`}>
                      {n.neighbor_ip || '-'}
                      {n.peer_asn > 0 ? ` (AS${n.peer_asn})` : ''}
                    </td>
                    <td className="py-2.5 px-2.5">
                      <span
                        className={`px-2 py-0.5 rounded border text-[11px] font-semibold ${
                          isEst ? ui.badgeEmerald : isIdle ? ui.badgeAmber : ui.badgeRose
                        }`}
                      >
                        {n.session_state}
                      </span>
                    </td>
                    <td className="py-2.5 px-2.5">
                      {isEst ? (
                        <span
                          className={`px-2 py-0.5 rounded border text-[10px] font-semibold ${
                            n.add_path_rx ? ui.badgeEmerald : ui.badgeAmber
                          }`}
                        >
                          {n.add_path_rx ? 'RX ON' : 'OFF'}
                        </span>
                      ) : (
                        <span className={ui.textSecondary}>-</span>
                      )}
                    </td>
                    <td className={`py-2.5 px-2.5 ${ui.textPrimary}`}>
                      {n.prefixes_ipv4.toLocaleString()} / {n.prefixes_ipv6.toLocaleString()}
                    </td>
                    <td className={`py-2.5 px-2.5 ${ui.textSecondary}`}>
                      {n.updates_received > 0 ? n.updates_received.toLocaleString() : '-'}
                    </td>
                    <td className={`py-2.5 px-2.5 ${ui.textSecondary}`}>{n.uptime || '-'}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
