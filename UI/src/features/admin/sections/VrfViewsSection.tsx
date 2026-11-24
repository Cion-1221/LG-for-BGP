// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { api } from '../../../api';
import { ThemeTokens } from '../../../hooks/useTheme';
import { BootstrapResponse, RouteViewMeta, RRNodeConfig } from '../../../types';

interface VrfViewsSectionProps {
  boot: BootstrapResponse;
  ui: ThemeTokens;
  popNameByID: Map<string, string>;
  rrNodeByID: Map<string, RRNodeConfig>;
  setAdminMsg: (msg: string) => void;
  reloadAll: () => Promise<void>;
}

const createBlankView = (): RouteViewMeta => ({
  id: '',
  name: '',
  vrf_name: '',
  type: 'auto',
  pop: '',
  rr_node_ids: ['all'],
  short_name: '',
  junos_context_type: 'routing-instances',
  junos_context_name: '',
  junos_table: '',
  juniper_source_ipv4: '',
  juniper_source_ipv6: '',
  bird_table_v4: '',
  bird_table_v6: '',
  frr_view_name: '',
  description: '',
  badge_color: 'blue',
});

export const VrfViewsSection: React.FC<VrfViewsSectionProps> = ({
  boot,
  ui,
  popNameByID,
  rrNodeByID,
  setAdminMsg,
  reloadAll,
}) => {
  const [editingView, setEditingView] = useState<RouteViewMeta>(createBlankView());

  return (
    <div className={`${ui.bgCard} border rounded-2xl p-6 space-y-6 text-xs`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className={`text-base font-bold ${ui.textPrimary} mb-1`}>
            VRF / Routing Table Management (Bound to RR Nodes)
          </h2>
          <p className={ui.textSecondary}>
            Bind each VRF / RIB table to <b>1 RR node</b>, <b>multiple RR nodes</b>, or{' '}
            <b>All RR Nodes</b>. Leave <b>VRF Name</b> blank or enter{' '}
            <code className="text-sky-700 dark:text-sky-400">global</code> for a single global
            table. For BIRD 2 Multi-VRF, IPv6 defaults to{' '}
            <code className="text-sky-700 dark:text-sky-400">&lt;VRF&gt;-v6</code> unless overridden.
          </p>
        </div>
        {editingView.id && (
          <button
            type="button"
            onClick={() => setEditingView(createBlankView())}
            className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold shrink-0"
          >
            + New VRF Form
          </button>
        )}
      </div>

      {boot.all_views.length === 0 ? (
        <div className={`p-6 rounded-xl border text-center ${ui.bgSubCard} ${ui.textSecondary}`}>
          No VRF / Routing Table views configured yet. Use the form below to add your first routing
          table.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {boot.all_views.map((v) => {
            const boundIDs = v.rr_node_ids || [];
            const isAllRRs = boundIDs.length === 1 && boundIDs[0].toLowerCase() === 'all';
            return (
              <div
                key={v.id}
                className={`p-4 rounded-xl border flex justify-between items-start gap-3 ${ui.bgSubCard}`}
              >
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`font-bold text-sm ${ui.textPrimary}`}>{v.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30 font-mono uppercase font-semibold">
                      {!v.type || v.type === 'auto'
                        ? 'AUTO (FOLLOW RR)'
                        : v.type === 'gobgp'
                          ? 'GOBGP (gRPC)'
                          : v.type}
                    </span>
                  </div>
                  <div className="font-mono text-sky-700 dark:text-sky-400">
                    VRF Name: <span className={ui.textPrimary}>{v.vrf_name}</span> · ID: {v.id}
                    {v.bird_table_v6 ? ` · BIRD v6: ${v.bird_table_v6}` : ''}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                    <span className={`font-medium ${ui.textSecondary}`}>Bound RRs:</span>
                    {isAllRRs ? (
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded border font-mono font-semibold ${ui.badgeSky}`}
                      >
                        ALL RR Nodes
                      </span>
                    ) : boundIDs.length === 0 ? (
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded border font-mono font-semibold ${ui.badgeAmber}`}
                      >
                        Unbound (Select RR)
                      </span>
                    ) : (
                      boundIDs.map((rid) => {
                        const rr = rrNodeByID.get(rid);
                        return (
                          <span
                            key={rid}
                            className={`text-[10px] px-2 py-0.5 rounded border font-mono ${ui.badgeSky}`}
                          >
                            {rr
                              ? `${popNameByID.get(rr.location.toUpperCase()) || rr.location} · ${rr.name} [${rr.engine_type}]`
                              : rid}
                          </span>
                        );
                      })
                    )}
                  </div>
                  {v.juniper_source_ipv4 && (
                    <div className={`font-mono ${ui.textSecondary}`}>
                      Neighbor Peer IP Filter: {v.juniper_source_ipv4}
                    </div>
                  )}
                  {v.description && <div className={ui.textSecondary}>{v.description}</div>}
                </div>
                <div className="flex gap-1.5 shrink-0">
                  <button
                    onClick={() =>
                      setEditingView({
                        ...v,
                        vrf_name: v.vrf_name || v.junos_context_name || '',
                        type: v.type || 'auto',
                        bird_table_v6: v.bird_table_v6 || '',
                        rr_node_ids:
                          v.rr_node_ids && v.rr_node_ids.length > 0 ? [...v.rr_node_ids] : ['all'],
                      })
                    }
                    className="px-2.5 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-700 dark:text-sky-400 font-medium"
                  >
                    Edit
                  </button>
                  <button
                    onClick={async () => {
                      try {
                        await api.deleteRouteView(v.id);
                        setAdminMsg(`Deleted VRF table ${v.name}`);
                        await reloadAll();
                      } catch (err: unknown) {
                        setAdminMsg(err instanceof Error ? err.message : 'Delete failed');
                      }
                    }}
                    className="px-2.5 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 font-medium"
                  >
                    Delete
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <form
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            const vrfVal = editingView.vrf_name.trim() || 'global';
            const rrIDs =
              editingView.rr_node_ids && editingView.rr_node_ids.length > 0
                ? editingView.rr_node_ids
                : ['all'];
            const payload: RouteViewMeta = {
              ...editingView,
              vrf_name: vrfVal,
              type: editingView.type || 'auto',
              rr_node_ids: rrIDs,
              short_name: vrfVal === 'global' ? 'GLOBAL' : vrfVal,
              junos_context_name: vrfVal,
              junos_table: `${vrfVal}.inet.0`,
              bird_table_v4: vrfVal === 'global' ? 'master4' : vrfVal,
              bird_table_v6: editingView.bird_table_v6.trim(),
              frr_view_name: vrfVal,
            };
            await api.saveRouteView(payload);
            setAdminMsg(
              `Saved VRF table: ${editingView.name} (${vrfVal} · RRs: ${rrIDs.join(', ')})`
            );
            setEditingView(createBlankView());
            await reloadAll();
          } catch (err: unknown) {
            setAdminMsg(err instanceof Error ? err.message : 'Save failed');
          }
        }}
        className={`pt-5 border-t ${ui.borderSubtle} space-y-4`}
      >
        <h3 className={`text-sm font-bold ${ui.textPrimary}`}>
          {editingView.id
            ? `Edit VRF / Routing Table (${editingView.id})`
            : 'Add New VRF / Routing Table'}
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3.5">
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              1. Display Name (Name) *
            </label>
            <input
              type="text"
              required
              value={editingView.name}
              onChange={(e) => setEditingView({ ...editingView, name: e.target.value })}
              placeholder="e.g. CN Optimized Routing"
              className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              2. VRF Name <span className={ui.textSky}>[Blank/global = Global]</span>
            </label>
            <input
              type="text"
              value={editingView.vrf_name}
              onChange={(e) =>
                setEditingView({
                  ...editingView,
                  vrf_name: e.target.value,
                  short_name: e.target.value || 'GLOBAL',
                  junos_context_name: e.target.value || 'global',
                })
              }
              placeholder="e.g. LSYS-OPT"
              className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>3. Engine Mode</label>
            <select
              value={editingView.type || 'auto'}
              onChange={(e) => setEditingView({ ...editingView, type: e.target.value })}
              className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            >
              <option value="auto">auto (Follow Bound RR&apos;s Engine)</option>
              <option value="gobgp">gobgp (GoBGP gRPC)</option>
              <option value="bird2">bird2 (BIRD 2 Table)</option>
              <option value="frr">frr (FRR View / VyOS VRF)</option>
            </select>
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              4. BIRD 2 IPv6 Table (Optional)
            </label>
            <input
              type="text"
              value={editingView.bird_table_v6}
              onChange={(e) => setEditingView({ ...editingView, bird_table_v6: e.target.value })}
              placeholder={
                !editingView.vrf_name.trim() || editingView.vrf_name.trim().toLowerCase() === 'global'
                  ? 'master6 (Auto)'
                  : `${editingView.vrf_name.trim()}-v6 (Auto)`
              }
              className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              5. Neighbor Peer IPv4 (Optional)
            </label>
            <input
              type="text"
              value={editingView.juniper_source_ipv4}
              onChange={(e) =>
                setEditingView({ ...editingView, juniper_source_ipv4: e.target.value })
              }
              placeholder="Match by VRF if blank"
              className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
        </div>

        <div>
          <label className={`block font-medium mb-2 ${ui.textSecondary}`}>
            6. Bound RR Collector Nodes * (Bind to 1 RR, multiple RRs, or All RR Nodes)
          </label>
          <div className="flex flex-wrap gap-2">
            {(() => {
              const curIDs = editingView.rr_node_ids || [];
              const isAll = curIDs.length === 1 && curIDs[0].toLowerCase() === 'all';
              return (
                <>
                  <button
                    type="button"
                    onClick={() =>
                      setEditingView({
                        ...editingView,
                        rr_node_ids: isAll
                          ? boot.rr_nodes.length > 0
                            ? [boot.rr_nodes[0].id]
                            : ['all']
                          : ['all'],
                      })
                    }
                    className={`px-3 py-2 rounded-xl border font-semibold transition flex items-center gap-2 ${
                      isAll
                        ? 'bg-indigo-600 text-white border-indigo-500 shadow-sm'
                        : `${ui.bgSubCard} ${ui.textPrimary} hover:opacity-85`
                    }`}
                  >
                    <span>{isAll ? '✓' : '○'}</span>
                    <span>All RR Nodes</span>
                  </button>

                  {boot.rr_nodes.map((rr) => {
                    const checked = !isAll && curIDs.includes(rr.id);
                    const popLabel = popNameByID.get(rr.location.toUpperCase()) || rr.location;
                    return (
                      <button
                        key={rr.id}
                        type="button"
                        onClick={() => {
                          const base = isAll ? [] : [...curIDs];
                          const next = checked
                            ? base.filter((id) => id !== rr.id)
                            : [...base, rr.id];
                          setEditingView({
                            ...editingView,
                            rr_node_ids: next.length > 0 ? next : ['all'],
                          });
                        }}
                        className={`px-3 py-2 rounded-xl border transition flex items-center gap-2 ${
                          checked
                            ? ui.isDark
                              ? 'bg-sky-500/20 border-sky-500 text-white shadow-sm'
                              : 'bg-sky-50 border-sky-500 text-sky-950 shadow-sm'
                            : `${ui.bgSubCard} ${ui.textSecondary} hover:opacity-90`
                        }`}
                      >
                        <span
                          className={`w-3.5 h-3.5 rounded flex items-center justify-center border text-[10px] ${
                            checked
                              ? 'bg-sky-600 border-sky-500 text-white font-bold'
                              : ui.isDark
                                ? 'border-slate-600'
                                : 'border-slate-400 bg-white'
                          }`}
                        >
                          {checked ? '✓' : ''}
                        </span>
                        <span className={`font-semibold ${checked ? '' : ui.textPrimary}`}>
                          {rr.name}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${ui.badgeSky}`}
                        >
                          {popLabel}
                        </span>
                        <span className={`text-[10px] font-mono uppercase ${ui.textSecondary}`}>
                          {rr.engine_type}
                        </span>
                      </button>
                    );
                  })}
                </>
              );
            })()}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              Custom View ID (Optional)
            </label>
            <input
              type="text"
              value={editingView.id}
              onChange={(e) => setEditingView({ ...editingView, id: e.target.value })}
              placeholder="Auto-generated if blank"
              className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div className="md:col-span-3">
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Description</label>
            <input
              type="text"
              value={editingView.description}
              onChange={(e) => setEditingView({ ...editingView, description: e.target.value })}
              placeholder="Optional description"
              className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
            />
          </div>
        </div>
        <button
          type="submit"
          className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition"
        >
          Save VRF Configuration
        </button>
      </form>
    </div>
  );
};
