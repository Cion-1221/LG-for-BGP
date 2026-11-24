// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../../api';
import { Footer } from '../../components/common/Footer';
import { ThemeSwitcher } from '../../components/common/ThemeSwitcher';
import { ThemeTokens } from '../../hooks/useTheme';
import {
  BootstrapResponse,
  LookupResponse,
  POPGroup,
  QueryType,
  RouteViewID,
  ThemeMode,
} from '../../types';
import { computeVisiblePermittedViews } from '../../utils/topology';
import { CliResultWindow } from './CliResultWindow';
import { CustomerLoginCard } from './CustomerLoginCard';
import { QueryCommandPanel } from './QueryCommandPanel';

interface LookingGlassPortalProps {
  boot: BootstrapResponse;
  ui: ThemeTokens;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  activePOPGroups: POPGroup[];
  onLogin: (username: string, password: string) => Promise<void>;
  onLogout: () => void;
  onOpenPasswordModal: () => void;
}

export const LookingGlassPortal: React.FC<LookingGlassPortalProps> = ({
  boot,
  ui,
  themeMode,
  setThemeMode,
  activePOPGroups,
  onLogin,
  onLogout,
  onOpenPasswordModal,
}) => {
  const [queryType, setQueryType] = useState<QueryType>('prefix');
  const [target, setTarget] = useState('');
  const [selectedPOP, setSelectedPOP] = useState<string>('');
  const [selectedViews, setSelectedViews] = useState<RouteViewID[]>([]);
  const [lookupResult, setLookupResult] = useState<LookupResponse | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState('');

  useEffect(() => {
    if (
      activePOPGroups.length > 0 &&
      (!selectedPOP ||
        !activePOPGroups.some((p) => p.id.toLowerCase() === selectedPOP.toLowerCase()))
    ) {
      setSelectedPOP(activePOPGroups[0].id);
    }
  }, [activePOPGroups, selectedPOP]);

  const visiblePermittedViews = useMemo(
    () => computeVisiblePermittedViews(boot, selectedPOP),
    [boot, selectedPOP]
  );

  useEffect(() => {
    const visibleIDs = visiblePermittedViews.map((v) => v.id);
    setSelectedViews((prev) => {
      const valid = prev.filter((id) => visibleIDs.includes(id));
      return valid.length > 0 ? valid : visibleIDs;
    });
  }, [visiblePermittedViews]);

  const isAuthRequiredMode = boot.settings.access_mode === 'auth_required';
  const requiresCustomerLoginGate = isAuthRequiredMode && !boot.current_user;
  const activePOPObj =
    activePOPGroups.find((p) => p.id.toLowerCase() === selectedPOP.toLowerCase()) ||
    activePOPGroups[0];
  const activePOPDisplay = activePOPObj
    ? activePOPObj.name !== activePOPObj.id
      ? `${activePOPObj.name} (${activePOPObj.id})`
      : activePOPObj.id
    : boot.settings.datacenter_code;

  const handleRunLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    const queryVal = target.trim();
    if (!queryVal) {
      setLookupError('Please enter a target IPv4/IPv6 address, prefix, ASN, or BGP community.');
      return;
    }
    if (selectedViews.length === 0) {
      setLookupError('Please select at least one VRF / Routing Table view.');
      return;
    }

    setLookupLoading(true);
    setLookupError('');
    try {
      const res = await api.lookupBGP({
        query_type: queryType,
        target: queryVal,
        views: selectedViews,
        pop: selectedPOP || activePOPGroups[0]?.id || 'all',
        rr_node_id: 'auto',
        engine: 'auto',
      });
      setLookupResult(res);
    } catch (err: unknown) {
      setLookupError(err instanceof Error ? err.message : 'Query execution failed');
    } finally {
      setLookupLoading(false);
    }
  };

  return (
    <div className={`min-h-screen ${ui.bgPage} flex flex-col font-sans transition-colors duration-150`}>
      <header className={`border-b ${ui.bgHeader} backdrop-blur sticky top-0 z-30`}>
        <div className={`${ui.layoutContainer} py-3.5 flex flex-wrap items-center justify-between gap-4`}>
          <div className="flex items-center gap-3.5">
            {boot.settings.portal_logo ? (
              <div
                className={`w-10 h-10 rounded-xl border flex items-center justify-center overflow-hidden p-0.5 shrink-0 ${
                  ui.isDark ? 'bg-[#0b101d] border-slate-800' : 'bg-white border-slate-200 shadow-sm'
                }`}
              >
                <img
                  src={boot.settings.portal_logo}
                  alt={boot.settings.organization_name}
                  className="w-full h-full object-contain rounded-lg"
                />
              </div>
            ) : (
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center font-bold text-sm text-white shadow-lg shadow-sky-500/20 shrink-0">
                BGP
              </div>
            )}
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <span className={`font-bold text-base tracking-tight ${ui.textPrimary}`}>
                  {boot.settings.organization_name}
                </span>
                <span
                  className={`text-[11px] px-2 py-0.5 rounded-md border font-mono font-semibold ${ui.badgeSky}`}
                >
                  AS{boot.settings.primary_asn}
                </span>
                <span
                  className={`text-[11px] px-2 py-0.5 rounded-md border font-mono ${
                    ui.isDark
                      ? 'bg-slate-800/90 text-slate-300 border-slate-700/80'
                      : 'bg-slate-100 text-slate-700 border-slate-300'
                  }`}
                >
                  {activePOPDisplay}
                </span>
              </div>
              <p className={`text-xs ${ui.textSecondary} mt-0.5`}>
                Carrier-Grade Real-Time BGP Routing Table Looking Glass
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <ThemeSwitcher themeMode={themeMode} setThemeMode={setThemeMode} isDark={ui.isDark} />

            {isAuthRequiredMode && boot.current_user && (
              <div
                className={`flex items-center gap-2.5 border rounded-xl px-3.5 py-1.5 ${ui.bgSubCard}`}
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className={`font-semibold ${ui.textPrimary}`}>
                  {boot.current_user.display_name || boot.current_user.username}
                </span>
                <button
                  onClick={onOpenPasswordModal}
                  className={`${ui.textSky} hover:underline ml-1 font-medium`}
                >
                  Password
                </button>
                <button
                  onClick={() => {
                    setLookupResult(null);
                    onLogout();
                  }}
                  className={`${ui.textRose} hover:underline ml-1 font-medium`}
                >
                  Sign Out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className={`${ui.layoutContainer} py-6 flex-1`}>
        {requiresCustomerLoginGate ? (
          <CustomerLoginCard
            ui={ui}
            organizationName={boot.settings.organization_name}
            onLogin={onLogin}
          />
        ) : (
          <div className="space-y-5">
            <QueryCommandPanel
              ui={ui}
              activePOPGroups={activePOPGroups}
              activePOPDisplay={activePOPDisplay}
              selectedPOP={selectedPOP}
              onSelectPOP={(popID) => {
                if (selectedPOP.toLowerCase() !== popID.toLowerCase()) {
                  setSelectedPOP(popID);
                  setQueryType('prefix');
                  setSelectedViews([]);
                  setTarget('');
                  setLookupResult(null);
                  setLookupError('');
                }
              }}
              queryType={queryType}
              onSelectQueryType={(qt) => {
                if (queryType !== qt) {
                  setQueryType(qt);
                  setTarget('');
                  setLookupResult(null);
                  setLookupError('');
                }
              }}
              visiblePermittedViews={visiblePermittedViews}
              selectedViews={selectedViews}
              onToggleView={(id) =>
                setSelectedViews((prev) =>
                  prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
                )
              }
              onSelectAllViews={() => setSelectedViews(visiblePermittedViews.map((v) => v.id))}
              onClearViews={() => setSelectedViews([])}
              target={target}
              onChangeTarget={setTarget}
              lookupLoading={lookupLoading}
              lookupError={lookupError}
              onRunLookup={handleRunLookup}
            />

            {lookupResult && (
              <div className="space-y-5">
                {lookupResult.results.map((viewRes) => (
                  <CliResultWindow key={viewRes.view.id} ui={ui} viewRes={viewRes} />
                ))}
              </div>
            )}
          </div>
        )}
      </main>
      <Footer ui={ui} />
    </div>
  );
};
