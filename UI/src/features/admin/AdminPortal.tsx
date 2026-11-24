// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../../api';
import { Footer } from '../../components/common/Footer';
import { ThemeSwitcher } from '../../components/common/ThemeSwitcher';
import { ThemeTokens } from '../../hooks/useTheme';
import {
  AdminSectionID,
  AuditLogEntry,
  BGPNeighborSummary,
  BootstrapResponse,
  LoginLockEntry,
  POPGroup,
  RouteViewMeta,
  RRNodeConfig,
  ThemeMode,
  UserAccount,
} from '../../types';
import { AdminLoginCard } from './AdminLoginCard';
import { GlobalSettingsSection } from './sections/GlobalSettingsSection';
import { PopAndRrSection } from './sections/PopAndRrSection';
import { SecurityAuditSection } from './sections/SecurityAuditSection';
import { UsersRbacSection } from './sections/UsersRbacSection';
import { VrfViewsSection } from './sections/VrfViewsSection';

interface AdminPortalProps {
  boot: BootstrapResponse;
  setBoot: React.Dispatch<React.SetStateAction<BootstrapResponse | null>>;
  ui: ThemeTokens;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  configuredPOPGroups: POPGroup[];
  adminMsg: string;
  setAdminMsg: (msg: string) => void;
  onLogin: (username: string, password: string) => Promise<void>;
  onLogout: () => void;
  onSwitchToLG: () => void;
  onOpenPasswordModal: () => void;
  reloadBootstrap: () => Promise<void>;
}

export const AdminPortal: React.FC<AdminPortalProps> = ({
  boot,
  setBoot,
  ui,
  themeMode,
  setThemeMode,
  configuredPOPGroups,
  adminMsg,
  setAdminMsg,
  onLogin,
  onLogout,
  onSwitchToLG,
  onOpenPasswordModal,
  reloadBootstrap,
}) => {
  const [adminSection, setAdminSection] = useState<AdminSectionID>('settings');
  const [neighbors, setNeighbors] = useState<BGPNeighborSummary[]>([]);
  const [neighborsLoading, setNeighborsLoading] = useState(false);
  const [neighborsUpdatedAt, setNeighborsUpdatedAt] = useState<string>('');
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loginLocks, setLoginLocks] = useState<LoginLockEntry[]>([]);

  const isAdminAuthenticated = boot.current_user?.role === 'admin';
  const mustChangePassword = !!boot.current_user?.must_change_password;

  const refreshNeighbors = useCallback(async () => {
    setNeighborsLoading(true);
    try {
      const sum = await api.getSummary();
      setNeighbors(sum.neighbors || []);
      setNeighborsUpdatedAt(new Date().toLocaleTimeString());
    } catch (e) {
      console.error(e);
    } finally {
      setNeighborsLoading(false);
    }
  }, []);

  const loadAdminData = useCallback(async () => {
    if (!isAdminAuthenticated || mustChangePassword) return;
    setNeighborsLoading(true);
    try {
      const [uList, logs, locks, sum] = await Promise.all([
        api.getUsers(),
        api.getAuditLogs(),
        api.getLoginLocks().catch(() => []),
        api.getSummary().catch(() => ({ neighbors: [] })),
      ]);
      setUsers(uList || []);
      setAuditLogs(logs || []);
      setLoginLocks(locks || []);
      setNeighbors(sum.neighbors || []);
      setNeighborsUpdatedAt(new Date().toLocaleTimeString());
    } catch (e) {
      console.error(e);
    } finally {
      setNeighborsLoading(false);
    }
  }, [isAdminAuthenticated, mustChangePassword]);

  useEffect(() => {
    if (isAdminAuthenticated && !mustChangePassword) {
      loadAdminData();
    }
  }, [isAdminAuthenticated, mustChangePassword, adminSection, loadAdminData]);

  const reloadAll = useCallback(async () => {
    await reloadBootstrap();
    await loadAdminData();
  }, [reloadBootstrap, loadAdminData]);

  const viewByID = useMemo(() => {
    const m = new Map<string, RouteViewMeta>();
    for (const v of boot.all_views || []) m.set(v.id, v);
    return m;
  }, [boot.all_views]);

  const popNameByID = useMemo(() => {
    const m = new Map<string, string>();
    for (const p of configuredPOPGroups) m.set(p.id.toUpperCase(), p.name);
    return m;
  }, [configuredPOPGroups]);

  const rrNodeByID = useMemo(() => {
    const m = new Map<string, RRNodeConfig>();
    for (const n of boot.rr_nodes || []) m.set(n.id, n);
    return m;
  }, [boot.rr_nodes]);

  const activeLockedCount = useMemo(
    () => loginLocks.filter((l) => l.locked).length,
    [loginLocks]
  );

  if (!isAdminAuthenticated) {
    return (
      <AdminLoginCard
        ui={ui}
        themeMode={themeMode}
        setThemeMode={setThemeMode}
        onLogin={onLogin}
      />
    );
  }

  return (
    <div className={`min-h-screen ${ui.bgPage} flex flex-col font-sans`}>
      <header className={`border-b ${ui.bgHeader} backdrop-blur sticky top-0 z-30`}>
        <div
          className={`${ui.layoutContainer} py-3.5 flex flex-wrap items-center justify-between gap-4`}
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 text-slate-950 font-bold flex items-center justify-center text-xs shadow-md shadow-amber-500/10">
              ADM
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className={`font-bold text-base tracking-tight ${ui.textPrimary}`}>
                  BGP Looking Glass Administration
                </span>
                <span
                  className={`text-[11px] px-2 py-0.5 rounded-md border font-mono font-semibold ${ui.badgeAmber}`}
                >
                  CONTROL PLANE
                </span>
              </div>
              <p className={`text-xs ${ui.textSecondary}`}>
                PoP Groups & Multi-RR Configuration · VRF Views · RBAC · Audit Logs
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 text-xs">
            <ThemeSwitcher themeMode={themeMode} setThemeMode={setThemeMode} isDark={ui.isDark} />
            <button
              onClick={onSwitchToLG}
              className={`px-3.5 py-1.5 rounded-lg border font-medium transition hover:opacity-85 ${ui.badgeSky}`}
            >
              ↗ Public Looking Glass
            </button>
            <button
              onClick={onOpenPasswordModal}
              className={`px-3 py-1.5 rounded-lg border ${ui.bgSubCard} ${ui.textPrimary} hover:opacity-80 transition`}
            >
              Change Password
            </button>
            <span className={`font-mono ${ui.textSecondary}`}>{boot.current_user?.username}</span>
            <button
              onClick={onLogout}
              className={`px-2.5 py-1.5 rounded-lg hover:bg-rose-500/10 font-medium transition ${ui.textRose}`}
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <div className={`${ui.layoutContainer} py-6 flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6`}>
        <aside className="lg:col-span-3 xl:col-span-2 space-y-1.5 text-xs">
          {(
            [
              {
                id: 'settings',
                label: '1. Global & Access Policy',
                badge: boot.settings.access_mode,
              },
              {
                id: 'rr',
                label: '2. PoP Groups & RR Nodes',
                badge: `${configuredPOPGroups.length} PoP / ${boot.rr_nodes.length} RR`,
              },
              {
                id: 'views',
                label: '3. VRF / Routing Tables',
                badge: String(boot.all_views.length),
              },
              {
                id: 'users',
                label: '4. User Accounts & RBAC',
                badge: String(users.length),
              },
              {
                id: 'logs',
                label: '5. Security, Audit & Cache',
                badge: activeLockedCount > 0 ? `${activeLockedCount} locked` : '',
              },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setAdminSection(item.id);
                setAdminMsg('');
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium transition ${
                adminSection === item.id
                  ? 'bg-gradient-to-r from-amber-500 to-orange-500 text-slate-950 font-semibold shadow-md shadow-amber-500/10'
                  : `${ui.bgCard} ${ui.textPrimary} hover:opacity-90 border`
              }`}
            >
              <span>{item.label}</span>
              {item.badge && (
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                    adminSection === item.id
                      ? 'bg-slate-950/20 text-slate-950 font-bold'
                      : ui.isDark
                        ? 'bg-slate-800 text-slate-300'
                        : 'bg-slate-100 text-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          ))}
        </aside>

        <section className="lg:col-span-9 xl:col-span-10 space-y-5">
          {adminMsg && (
            <div
              className={`p-3.5 rounded-xl border text-xs flex justify-between items-center font-medium ${ui.badgeEmerald}`}
            >
              <span>{adminMsg}</span>
              <button
                onClick={() => setAdminMsg('')}
                className={`${ui.textSecondary} hover:opacity-80 px-1.5`}
              >
                ✕
              </button>
            </div>
          )}

          {!mustChangePassword && adminSection === 'settings' && (
            <GlobalSettingsSection
              boot={boot}
              setBoot={setBoot}
              ui={ui}
              rrNodeByID={rrNodeByID}
              setAdminMsg={setAdminMsg}
              reloadBootstrap={reloadBootstrap}
            />
          )}

          {!mustChangePassword && adminSection === 'rr' && (
            <PopAndRrSection
              boot={boot}
              ui={ui}
              configuredPOPGroups={configuredPOPGroups}
              popNameByID={popNameByID}
              neighbors={neighbors}
              neighborsLoading={neighborsLoading}
              neighborsUpdatedAt={neighborsUpdatedAt}
              onRefreshNeighbors={refreshNeighbors}
              setAdminMsg={setAdminMsg}
              reloadAll={reloadAll}
            />
          )}

          {!mustChangePassword && adminSection === 'views' && (
            <VrfViewsSection
              boot={boot}
              ui={ui}
              popNameByID={popNameByID}
              rrNodeByID={rrNodeByID}
              setAdminMsg={setAdminMsg}
              reloadAll={reloadAll}
            />
          )}

          {!mustChangePassword && adminSection === 'users' && (
            <UsersRbacSection
              boot={boot}
              ui={ui}
              users={users}
              viewByID={viewByID}
              setAdminMsg={setAdminMsg}
              reloadAll={reloadAll}
            />
          )}

          {!mustChangePassword && adminSection === 'logs' && (
            <SecurityAuditSection
              ui={ui}
              auditLogs={auditLogs}
              loginLocks={loginLocks}
              setLoginLocks={setLoginLocks}
              setAdminMsg={setAdminMsg}
              reloadAdminData={loadAdminData}
            />
          )}
        </section>
      </div>
      <Footer ui={ui} />
    </div>
  );
};
