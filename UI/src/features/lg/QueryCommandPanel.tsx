// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React from 'react';
import { ThemeTokens } from '../../hooks/useTheme';
import { POPGroup, QueryType, RouteViewID, RouteViewMeta } from '../../types';

interface QueryCommandPanelProps {
  ui: ThemeTokens;
  activePOPGroups: POPGroup[];
  activePOPDisplay: string;
  selectedPOP: string;
  onSelectPOP: (popID: string) => void;
  queryType: QueryType;
  onSelectQueryType: (qt: QueryType) => void;
  visiblePermittedViews: RouteViewMeta[];
  selectedViews: RouteViewID[];
  onToggleView: (id: RouteViewID) => void;
  onSelectAllViews: () => void;
  onClearViews: () => void;
  target: string;
  onChangeTarget: (val: string) => void;
  lookupLoading: boolean;
  lookupError: string;
  onRunLookup: (e: React.FormEvent) => void;
}

export const QueryCommandPanel: React.FC<QueryCommandPanelProps> = ({
  ui,
  activePOPGroups,
  activePOPDisplay,
  selectedPOP,
  onSelectPOP,
  queryType,
  onSelectQueryType,
  visiblePermittedViews,
  selectedViews,
  onToggleView,
  onSelectAllViews,
  onClearViews,
  target,
  onChangeTarget,
  lookupLoading,
  lookupError,
  onRunLookup,
}) => (
  <div className={`${ui.bgCard} border rounded-2xl p-5 sm:p-6 space-y-4`}>
    {activePOPGroups.length > 1 && (
      <div className={`flex flex-wrap items-center gap-3 pb-3.5 border-b ${ui.borderSubtle}`}>
        <span className={`text-sm font-bold min-w-[88px] shrink-0 ${ui.textPrimary}`}>
          PoP Node:
        </span>
        <div
          className={`inline-flex flex-wrap p-1 rounded-xl border gap-1 ${
            ui.isDark ? 'bg-[#060911] border-slate-800/90' : 'bg-slate-100 border-slate-200'
          }`}
        >
          {activePOPGroups.map((pop) => {
            const active = selectedPOP.toLowerCase() === pop.id.toLowerCase();
            return (
              <button
                key={pop.id}
                type="button"
                onClick={() => onSelectPOP(pop.id)}
                className={`px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 ${
                  active
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : ui.isDark
                      ? 'text-slate-300 hover:text-white'
                      : 'text-slate-700 hover:text-slate-950'
                }`}
              >
                <span>{pop.name}</span>
                {pop.name !== pop.id && (
                  <span
                    className={`text-[11px] font-mono px-1.5 py-0.5 rounded font-medium ${
                      active
                        ? 'bg-white/20 text-white'
                        : ui.isDark
                          ? 'bg-slate-800 text-slate-300'
                          : 'bg-slate-200/90 text-slate-700'
                    }`}
                  >
                    {pop.id}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    )}

    <div className="flex flex-wrap items-center justify-between gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`text-xs font-semibold min-w-[88px] shrink-0 ${ui.textSecondary}`}>
          Query Type:
        </span>
        <div
          className={`inline-flex flex-wrap p-1 rounded-xl border gap-1 ${
            ui.isDark ? 'bg-[#060911] border-slate-800/90' : 'bg-slate-100 border-slate-200'
          }`}
        >
          {(
            [
              { id: 'prefix', label: 'IPv4 / IPv6 Prefix' },
              { id: 'aspath', label: 'ASN / AS-Path' },
              { id: 'community', label: 'BGP Community' },
            ] as const
          ).map((qt) => (
            <button
              key={qt.id}
              type="button"
              onClick={() => onSelectQueryType(qt.id)}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
                queryType === qt.id
                  ? 'bg-sky-600 text-white shadow-sm'
                  : ui.isDark
                    ? 'text-slate-400 hover:text-slate-200'
                    : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {qt.label}
            </button>
          ))}
        </div>
      </div>

      {visiblePermittedViews.length > 1 && (
        <div className="flex items-center gap-3 text-xs">
          <button
            type="button"
            onClick={onSelectAllViews}
            className={`${ui.textSky} hover:underline font-medium`}
          >
            Select All ({visiblePermittedViews.length})
          </button>
          <span className={ui.textSecondary}>|</span>
          <button type="button" onClick={onClearViews} className={`${ui.textSecondary} hover:underline`}>
            Clear
          </button>
        </div>
      )}
    </div>

    <div>
      <div className={`text-xs font-medium ${ui.textSecondary} mb-2`}>
        Routing Instances / VRF Tables:
      </div>
      {visiblePermittedViews.length === 0 ? (
        <div className={`p-4 rounded-xl border text-xs ${ui.bgSubCard} ${ui.textSecondary}`}>
          {activePOPDisplay
            ? `No routing tables / VRFs are currently configured for PoP ${activePOPDisplay}.`
            : 'No routing tables are currently assigned or configured.'}
        </div>
      ) : (
        <div className="flex flex-wrap gap-2.5">
          {visiblePermittedViews.map((view) => {
            const checked = selectedViews.includes(view.id);
            return (
              <button
                key={view.id}
                type="button"
                onClick={() => onToggleView(view.id)}
                className={`group flex items-center gap-2.5 px-3.5 py-2 rounded-xl border text-xs transition ${
                  checked
                    ? ui.isDark
                      ? 'bg-sky-500/15 border-sky-500/60 text-white shadow-sm'
                      : 'bg-sky-50 border-sky-500 text-sky-950 shadow-sm'
                    : `${ui.bgSubCard} ${ui.textSecondary} hover:opacity-90`
                }`}
              >
                <span
                  className={`w-3.5 h-3.5 rounded flex items-center justify-center border text-[10px] ${
                    checked
                      ? 'bg-sky-600 border-sky-500 text-white font-bold'
                      : ui.isDark
                        ? 'border-slate-500/60 bg-transparent'
                        : 'border-slate-400 bg-white'
                  }`}
                >
                  {checked ? '✓' : ''}
                </span>
                <span className="font-semibold">{view.name}</span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase ${
                    checked
                      ? ui.isDark
                        ? 'bg-sky-950/80 text-sky-200 border border-sky-500/30'
                        : 'bg-sky-100 text-sky-900 border border-sky-200'
                      : ui.isDark
                        ? 'bg-slate-800/90 text-slate-300'
                        : 'bg-slate-200/80 text-slate-700'
                  }`}
                >
                  {view.vrf_name}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>

    <form onSubmit={onRunLookup} className="flex flex-col sm:flex-row gap-3">
      <div className="relative flex-1">
        <input
          type="text"
          value={target}
          onChange={(e) => onChangeTarget(e.target.value)}
          placeholder={
            queryType === 'prefix'
              ? 'Enter IPv4/IPv6 address or CIDR prefix (e.g. 202.96.134.133 or 202.96.128.0/18)'
              : queryType === 'aspath'
                ? 'Enter ASN or AS-Path with optional ^ / $ anchors (e.g. 4134, ^2914, or 4134$)'
                : 'Enter BGP Community or Large Community (e.g. 23764:11100 or 65000:100:200)'
          }
          className={`w-full px-4 py-3 rounded-xl border text-sm font-mono ${ui.bgInput} focus:outline-none focus:border-sky-500 transition`}
        />
      </div>
      <button
        type="submit"
        disabled={lookupLoading || visiblePermittedViews.length === 0}
        className="px-7 py-3 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 disabled:opacity-40 text-white font-semibold text-sm transition shadow-lg shadow-sky-500/20 shrink-0"
      >
        {lookupLoading ? 'Querying RIB...' : 'Query Routes'}
      </button>
    </form>

    {lookupError && (
      <div className={`p-3.5 rounded-xl border text-xs font-mono ${ui.badgeRose}`}>
        {lookupError}
      </div>
    )}
  </div>
);
