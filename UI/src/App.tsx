import React, { useEffect, useMemo, useState } from 'react';
import { api, BootstrapResponse, setToken } from './api';
import {
  AuditLogEntry,
  BGPNeighborSummary,
  CommunityDictEntry,
  LookupResponse,
  POPGroup,
  RouteViewID,
  RouteViewMeta,
  RRNodeConfig,
  SystemSettings,
  UserAccount,
  ViewQueryResult,
} from './types';

type ThemeMode = 'light' | 'dark' | 'system';

function getCurrentEntrySlug(): string {
  const hash = window.location.hash.replace(/^#\/?/, '').trim();
  if (hash) return hash;
  return window.location.pathname.replace(/^\/+|\/+$/g, '').trim();
}

export const App: React.FC = () => {
  const [portalMode, setPortalMode] = useState<'lg' | 'admin' | 'notfound'>('lg');
  const [boot, setBoot] = useState<BootstrapResponse | null>(null);
  const [loadingBoot, setLoadingBoot] = useState(true);

  // Theme Mode: 'light' | 'dark' | 'system'
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('lg_theme_mode') as ThemeMode | null;
    if (saved === 'light' || saved === 'dark' || saved === 'system') return saved;
    return 'system';
  });
  const [systemPrefersDark, setSystemPrefersDark] = useState<boolean>(() =>
    typeof window !== 'undefined' && window.matchMedia
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
      : true
  );

  useEffect(() => {
    localStorage.setItem('lg_theme_mode', themeMode);
    if (!window.matchMedia) return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => setSystemPrefersDark(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [themeMode]);

  const isDark = themeMode === 'dark' || (themeMode === 'system' && systemPrefersDark);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
    document.body.style.backgroundColor = isDark ? '#060911' : '#f8fafc';
    document.body.style.color = isDark ? '#f1f5f9' : '#0f172a';
  }, [isDark]);

  const [adminSection, setAdminSection] = useState<
    'settings' | 'views' | 'rr' | 'users' | 'communities' | 'logs'
  >('settings');

  // Auth & Password Change States
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState('');

  const [showChangePwdModal, setShowChangePwdModal] = useState(false);
  const [curPwd, setCurPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdError, setPwdError] = useState('');

  // BGP Lookup & Multi-POP States
  const [queryType, setQueryType] = useState<'prefix' | 'aspath' | 'community'>('prefix');
  const [target, setTarget] = useState('');
  const [selectedPOP, setSelectedPOP] = useState<string>('');
  const [selectedViews, setSelectedViews] = useState<RouteViewID[]>([]);
  const [lookupResult, setLookupResult] = useState<LookupResponse | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState('');
  const [copiedViewID, setCopiedViewID] = useState<string | null>(null);

  // Admin Console States
  const [neighbors, setNeighbors] = useState<BGPNeighborSummary[]>([]);
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditPage, setAuditPage] = useState<number>(1);
  const [auditPageSize, setAuditPageSize] = useState<number>(20);
  const [adminMsg, setAdminMsg] = useState('');

  const [editingPOP, setEditingPOP] = useState<POPGroup>({
    id: '',
    name: '',
    description: '',
    sort_order: 10,
  });

  const [editingView, setEditingView] = useState<RouteViewMeta>({
    id: '',
    name: '',
    vrf_name: '',
    type: 'gobgp',
    pop: 'all',
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

  const [editingRR, setEditingRR] = useState<RRNodeConfig>({
    id: '',
    name: '',
    location: '',
    engine_type: 'gobgp',
    loopback_ip: '',
    endpoint: '127.0.0.1:50051',
    role: 'primary',
    enabled: true,
    healthy: true,
    last_checked: '',
  });

  const [editingUser, setEditingUser] = useState<{
    id?: string;
    username: string;
    password: string;
    display_name: string;
    company: string;
    customer_asn: number;
    role: 'admin' | 'noc' | 'customer';
    allowed_views: RouteViewID[];
    rate_limit_per_minute: number;
    enabled: boolean;
    must_change_password: boolean;
    notes: string;
  }>({
    username: '',
    password: '',
    display_name: '',
    company: '',
    customer_asn: 0,
    role: 'customer',
    allowed_views: [],
    rate_limit_per_minute: 60,
    enabled: true,
    must_change_password: true,
    notes: '',
  });

  const [editingComm, setEditingComm] = useState<CommunityDictEntry>({
    community: '',
    label: '',
    category: 'upstream',
    description: '',
  });

  // Compute all configured PoP groups (merging boot.pops and any active RR locations)
  const configuredPOPGroups = useMemo<POPGroup[]>(() => {
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
  }, [boot]);

  // Active PoP groups that have at least 1 enabled RR node (or all configured PoPs if no RR yet)
  const activePOPGroups = useMemo<POPGroup[]>(() => {
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
  }, [boot, configuredPOPGroups]);

  useEffect(() => {
    if (
      activePOPGroups.length > 0 &&
      (!selectedPOP ||
        !activePOPGroups.some((p) => p.id.toLowerCase() === selectedPOP.toLowerCase()))
    ) {
      setSelectedPOP(activePOPGroups[0].id);
    }
  }, [activePOPGroups, selectedPOP]);

  // Filter permitted VRF views for the currently selected POP
  const visiblePermittedViews = useMemo(() => {
    if (!boot) return [];
    const allPermitted = boot.permitted_views || [];
    if (!selectedPOP || activePOPGroups.length <= 1) return allPermitted;
    const filtered = allPermitted.filter(
      (v) =>
        !v.pop || v.pop.toLowerCase() === 'all' || v.pop.toLowerCase() === selectedPOP.toLowerCase()
    );
    return filtered.length > 0 ? filtered : allPermitted;
  }, [boot, selectedPOP, activePOPGroups]);

  useEffect(() => {
    const visibleIDs = visiblePermittedViews.map((v) => v.id);
    setSelectedViews((prev) => {
      const valid = prev.filter((id) => visibleIDs.includes(id));
      return valid.length > 0 ? valid : visibleIDs;
    });
  }, [visiblePermittedViews]);

  const switchPortal = (mode: 'lg' | 'admin', customSlug?: string) => {
    setPortalMode(mode);
    setLoginError('');
    setAdminMsg('');
    if (mode === 'admin') {
      const slug = customSlug || boot?.settings.admin_secret_slug || getCurrentEntrySlug();
      if (slug) {
        window.history.pushState({}, '', `/${slug.replace(/^\/+/, '')}`);
      }
    } else {
      window.history.pushState({}, '', '/');
    }
  };

  const loadBootstrap = async () => {
    try {
      setLoadingBoot(true);
      const entrySlug = getCurrentEntrySlug();
      const data = await api.bootstrap(entrySlug);
      setBoot(data);

      if (entrySlug === '') {
        setPortalMode('lg');
      } else if (data.admin_entry_verified) {
        setPortalMode('admin');
      } else {
        setPortalMode('notfound');
      }
    } catch (e: unknown) {
      console.error(e);
    } finally {
      setLoadingBoot(false);
    }
  };

  useEffect(() => {
    const onPopState = () => {
      loadBootstrap();
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    loadBootstrap();
  }, []);

  const handleLogin = async (e?: React.FormEvent, targetPortal?: 'lg' | 'admin') => {
    if (e) e.preventDefault();
    setLoginError('');
    try {
      const res = await api.login(username.trim(), password);
      setToken(res.token);
      setPassword('');
      if (targetPortal) {
        switchPortal(targetPortal);
      }
      await loadBootstrap();
    } catch (err: unknown) {
      setLoginError(err instanceof Error ? err.message : 'Authentication failed');
    }
  };

  const handleLogout = async () => {
    setToken(null);
    setLookupResult(null);
    setUsername('');
    setPassword('');
    await loadBootstrap();
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwdError('');
    if (newPwd.length < 6) {
      setPwdError('New password must be at least 6 characters long.');
      return;
    }
    if (newPwd !== confirmPwd) {
      setPwdError('New password and confirmation do not match.');
      return;
    }
    try {
      const res = await api.changePassword(curPwd, newPwd);
      setToken(res.token);
      setCurPwd('');
      setNewPwd('');
      setConfirmPwd('');
      setShowChangePwdModal(false);
      setAdminMsg('Password updated successfully.');
      await loadBootstrap();
    } catch (err: unknown) {
      setPwdError(err instanceof Error ? err.message : 'Failed to change password');
    }
  };

  const handleRunLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
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
        pop: selectedPOP || 'all',
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

  const toggleViewSelection = (id: RouteViewID) => {
    setSelectedViews((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const copyCLIOutput = (viewID: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedViewID(viewID);
    setTimeout(() => {
      setCopiedViewID((prev) => (prev === viewID ? null : prev));
    }, 1800);
  };

  const loadAdminData = async () => {
    if (boot?.current_user?.role !== 'admin') return;
    try {
      const [uList, logs, sum] = await Promise.all([
        api.getUsers(),
        api.getAuditLogs(),
        api.getSummary().catch(() => ({ neighbors: [] })),
      ]);
      setUsers(uList || []);
      setAuditLogs(logs || []);
      setNeighbors(sum.neighbors || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    if (portalMode === 'admin' && boot?.current_user?.role === 'admin') {
      loadAdminData();
    }
  }, [portalMode, adminSection, boot?.current_user?.role]);

  // Theme-adaptive surface classes
  const bgPage = isDark ? 'bg-[#060911] text-slate-100' : 'bg-slate-50 text-slate-900';
  const bgHeader = isDark
    ? 'bg-[#0b101d]/95 border-slate-800/80'
    : 'bg-white/95 border-slate-200 shadow-sm';
  const bgCard = isDark
    ? 'bg-[#0b101d] border-slate-800/90 shadow-2xl'
    : 'bg-white border-slate-200/90 shadow-sm';
  const bgSubCard = isDark ? 'bg-[#060911] border-slate-800' : 'bg-slate-50 border-slate-200';
  const bgInput = isDark
    ? 'bg-[#060911] border-slate-800 text-white placeholder:text-slate-500'
    : 'bg-white border-slate-300 text-slate-900 placeholder:text-slate-400';
  const textPrimary = isDark ? 'text-white' : 'text-slate-900';
  const textSecondary = isDark ? 'text-slate-400' : 'text-slate-500';
  const layoutContainer = 'w-full max-w-[96vw] 2xl:max-w-[95vw] mx-auto px-3 sm:px-5';

  const renderThemeSwitcher = () => (
    <div
      className={`inline-flex items-center p-0.5 rounded-xl border text-xs ${
        isDark ? 'bg-[#060911] border-slate-800' : 'bg-slate-100 border-slate-200'
      }`}
      title="Switch Theme Mode (Light / Dark / System Auto)"
    >
      {(
        [
          { id: 'light', label: '☀ Light' },
          { id: 'dark', label: '🌙 Dark' },
          { id: 'system', label: '💻 Auto' },
        ] as const
      ).map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => setThemeMode(t.id)}
          className={`px-2.5 py-1 rounded-lg font-medium transition text-[11px] ${
            themeMode === t.id
              ? isDark
                ? 'bg-sky-600 text-white shadow-sm'
                : 'bg-white text-slate-900 shadow-sm'
              : isDark
                ? 'text-slate-400 hover:text-slate-200'
                : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );

  if (loadingBoot || !boot) {
    return (
      <div className={`min-h-screen ${bgPage} flex items-center justify-center`}>
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 rounded-full border-2 border-sky-500 border-t-transparent animate-spin" />
          <div className={`text-sm font-medium ${textSecondary}`}>
            Initializing BGP Looking Glass...
          </div>
        </div>
      </div>
    );
  }

  const mustChangePasswordGate =
    (!!boot.current_user?.must_change_password &&
      (portalMode === 'admin' || boot.settings.access_mode === 'auth_required')) ||
    showChangePwdModal;

  const renderPasswordChangeModal = (isMandatory: boolean) => (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className={`${bgCard} border rounded-2xl max-w-md w-full p-6`}>
        <div className="flex items-center justify-between mb-2">
          <div>
            <h3 className={`font-bold text-base ${textPrimary}`}>
              {isMandatory ? 'Password Change Required' : 'Change Account Password'}
            </h3>
            <p className={`text-xs ${textSecondary}`}>Account: {boot.current_user?.username}</p>
          </div>
          {!isMandatory && (
            <button
              type="button"
              onClick={() => {
                setShowChangePwdModal(false);
                setPwdError('');
              }}
              className={`${textSecondary} hover:opacity-80 text-sm px-2 py-1`}
            >
              ✕
            </button>
          )}
        </div>

        <p className={`text-xs ${textSecondary} mb-4 leading-relaxed`}>
          {isMandatory
            ? 'For security, you must set a new password before continuing.'
            : 'Enter your current password and choose a new password.'}
        </p>

        {pwdError && (
          <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
            {pwdError}
          </div>
        )}

        <form onSubmit={handleChangePassword} className="space-y-3.5 text-xs">
          <div>
            <label className={`block font-medium mb-1 ${textSecondary}`}>Current Password</label>
            <input
              type="password"
              required
              value={curPwd}
              onChange={(e) => setCurPwd(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-lg border ${bgInput} focus:outline-none focus:border-sky-500`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${textSecondary}`}>
              New Password (minimum 6 characters)
            </label>
            <input
              type="password"
              required
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-lg border ${bgInput} focus:outline-none focus:border-sky-500`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${textSecondary}`}>
              Confirm New Password
            </label>
            <input
              type="password"
              required
              value={confirmPwd}
              onChange={(e) => setConfirmPwd(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-lg border ${bgInput} focus:outline-none focus:border-sky-500`}
            />
          </div>
          <div className="flex items-center gap-2 pt-2">
            {isMandatory && (
              <button
                type="button"
                onClick={handleLogout}
                className="px-4 py-2.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-white font-medium transition"
              >
                Sign Out
              </button>
            )}
            <button
              type="submit"
              className="flex-1 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
            >
              Update Password
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  if (portalMode === 'notfound') {
    return (
      <div className={`min-h-screen ${bgPage} flex flex-col items-center justify-center p-4`}>
        <div className={`max-w-md w-full ${bgCard} border rounded-2xl p-8 text-center space-y-4`}>
          <div className="text-3xl font-bold font-mono text-rose-500">404</div>
          <div className={`text-base font-semibold ${textPrimary}`}>Page Not Found</div>
          <p className={`text-xs ${textSecondary} leading-relaxed`}>
            The requested endpoint does not exist on this Looking Glass server.
          </p>
          <button
            onClick={() => switchPortal('lg')}
            className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition"
          >
            Return to Looking Glass
          </button>
        </div>
      </div>
    );
  }

  const viewByID = new Map<string, RouteViewMeta>();
  for (const v of boot.all_views || []) {
    viewByID.set(v.id, v);
  }

  const popNameByID = new Map<string, string>();
  for (const p of configuredPOPGroups) {
    popNameByID.set(p.id.toUpperCase(), p.name);
  }

  // Group RR nodes by PoP for Admin Console
  const rrsByPOP = new Map<string, RRNodeConfig[]>();
  for (const n of boot.rr_nodes || []) {
    const popKey = n.location?.trim() || boot.settings.datacenter_code || 'DEFAULT-POP';
    const list = rrsByPOP.get(popKey) || [];
    list.push(n);
    rrsByPOP.set(popKey, list);
  }

  // ============================================================================
  // PORTAL 2: DEDICATED ADMIN MANAGEMENT CONSOLE (ONLY VIA /<admin_path>)
  // ============================================================================
  if (portalMode === 'admin') {
    const isAdminAuthenticated = boot.current_user?.role === 'admin';

    if (!isAdminAuthenticated) {
      return (
        <div className={`min-h-screen ${bgPage} flex flex-col justify-center items-center p-4`}>
          <div className={`max-w-md w-full ${bgCard} border rounded-2xl p-7`}>
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 text-slate-950 font-bold flex items-center justify-center text-sm shadow-lg shadow-amber-500/20">
                  ADM
                </div>
                <div>
                  <h1 className={`text-base font-bold ${textPrimary}`}>Administration Console</h1>
                  <p className={`text-xs ${textSecondary}`}>BGP Looking Glass Control Plane</p>
                </div>
              </div>
              {renderThemeSwitcher()}
            </div>

            {loginError && (
              <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                {loginError}
              </div>
            )}

            <form onSubmit={(e) => handleLogin(e, 'admin')} className="space-y-4">
              <div>
                <label className={`block text-xs font-medium ${textSecondary} mb-1.5`}>
                  Administrator Username
                </label>
                <input
                  type="text"
                  required
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter admin username"
                  className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${bgInput} focus:outline-none focus:border-amber-500`}
                />
              </div>
              <div>
                <label className={`block text-xs font-medium ${textSecondary} mb-1.5`}>
                  Password
                </label>
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${bgInput} focus:outline-none focus:border-amber-500`}
                />
              </div>
              <button
                type="submit"
                className="w-full py-2.5 rounded-lg bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-slate-950 font-bold text-sm transition shadow-lg shadow-amber-500/20"
              >
                Sign In to Admin Console
              </button>
            </form>
          </div>
        </div>
      );
    }

    return (
      <div className={`min-h-screen ${bgPage} flex flex-col font-sans`}>
        {mustChangePasswordGate &&
          renderPasswordChangeModal(!!boot.current_user?.must_change_password)}

        <header className={`border-b ${bgHeader} backdrop-blur sticky top-0 z-30`}>
          <div className={`${layoutContainer} py-3.5 flex flex-wrap items-center justify-between gap-4`}>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 text-slate-950 font-bold flex items-center justify-center text-xs shadow-md shadow-amber-500/10">
                ADM
              </div>
              <div>
                <div className="flex items-center gap-2.5">
                  <span className={`font-bold text-base tracking-tight ${textPrimary}`}>
                    BGP Looking Glass Administration
                  </span>
                  <span className="text-[11px] px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-500 border border-amber-500/30 font-mono font-semibold">
                    CONTROL PLANE
                  </span>
                </div>
                <p className={`text-xs ${textSecondary}`}>
                  PoP Groups & Multi-RR Configuration · VRF Views · RBAC · Audit Logs
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 text-xs">
              {renderThemeSwitcher()}
              <button
                onClick={() => switchPortal('lg')}
                className="px-3.5 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-500 border border-sky-500/30 font-medium transition"
              >
                ↗ Public Looking Glass
              </button>
              <button
                onClick={() => {
                  setPwdError('');
                  setShowChangePwdModal(true);
                }}
                className={`px-3 py-1.5 rounded-lg border ${bgSubCard} ${textPrimary} hover:opacity-80 transition`}
              >
                Change Password
              </button>
              <span className={`font-mono ${textSecondary}`}>{boot.current_user?.username}</span>
              <button
                onClick={handleLogout}
                className="px-2.5 py-1.5 rounded-lg text-rose-500 hover:bg-rose-500/10 font-medium transition"
              >
                Sign Out
              </button>
            </div>
          </div>
        </header>

        <div className={`${layoutContainer} py-6 flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6`}>
          <aside className="lg:col-span-3 xl:col-span-2 space-y-1.5 text-xs">
            {(
              [
                {
                  id: 'settings',
                  label: '1. Global & Access Policy',
                  badge: boot.settings.access_mode,
                },
                {
                  id: 'views',
                  label: '2. VRF / Routing Tables',
                  badge: String(boot.all_views.length),
                },
                {
                  id: 'rr',
                  label: '3. PoP Groups & RR Nodes',
                  badge: `${configuredPOPGroups.length} PoP / ${boot.rr_nodes.length} RR`,
                },
                {
                  id: 'users',
                  label: '4. User Accounts & RBAC',
                  badge: String(users.length),
                },
                {
                  id: 'communities',
                  label: '5. Community Dictionary',
                  badge: String(boot.communities.length),
                },
                { id: 'logs', label: '6. Audit Logs & Cache', badge: '' },
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
                    : `${bgCard} ${textPrimary} hover:opacity-90 border`
                }`}
              >
                <span>{item.label}</span>
                {item.badge && (
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                      adminSection === item.id
                        ? 'bg-slate-950/20 text-slate-950 font-bold'
                        : isDark
                          ? 'bg-slate-800 text-slate-400'
                          : 'bg-slate-100 text-slate-600'
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
              <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-500 text-xs flex justify-between items-center font-medium">
                <span>{adminMsg}</span>
                <button
                  onClick={() => setAdminMsg('')}
                  className={`${textSecondary} hover:opacity-80 px-1.5`}
                >
                  ✕
                </button>
              </div>
            )}

            {/* SECTION 1: SYSTEM SETTINGS & ACCESS MODE */}
            {adminSection === 'settings' && (
              <div className={`${bgCard} border rounded-2xl p-6 space-y-6`}>
                <div>
                  <h2 className={`text-base font-bold ${textPrimary} mb-1`}>
                    Public Portal Access Policy
                  </h2>
                  <p className={`text-xs ${textSecondary} mb-4`}>
                    Control whether visitors opening the Looking Glass (/) can immediately run queries or must sign in with an authorized account first.
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div
                      onClick={async () => {
                        const updated: SystemSettings = {
                          ...boot.settings,
                          access_mode: 'public',
                        };
                        await api.updateSettings(updated);
                        setAdminMsg('Switched to Public Direct Query Mode (public).');
                        await loadBootstrap();
                      }}
                      className={`cursor-pointer p-4 rounded-xl border transition ${
                        boot.settings.access_mode === 'public'
                          ? 'bg-emerald-500/10 border-emerald-500/60'
                          : `${bgSubCard} opacity-75 hover:opacity-100`
                      }`}
                    >
                      <div className="font-bold text-sm text-emerald-500 mb-1">
                        Public Direct Query Mode
                      </div>
                      <p className={`text-xs ${textSecondary} leading-relaxed`}>
                        Visitors opening / immediately query permitted public VRF views without any login button or admin link shown.
                      </p>
                    </div>

                    <div
                      onClick={async () => {
                        const updated: SystemSettings = {
                          ...boot.settings,
                          access_mode: 'auth_required',
                        };
                        await api.updateSettings(updated);
                        setAdminMsg('Switched to Authenticated Per-Customer Mode (auth_required).');
                        await loadBootstrap();
                      }}
                      className={`cursor-pointer p-4 rounded-xl border transition ${
                        boot.settings.access_mode === 'auth_required'
                          ? 'bg-amber-500/10 border-amber-500/60'
                          : `${bgSubCard} opacity-75 hover:opacity-100`
                      }`}
                    >
                      <div className="font-bold text-sm text-amber-500 mb-1">
                        Authenticated Account Mode
                      </div>
                      <p className={`text-xs ${textSecondary} leading-relaxed`}>
                        Requires users to sign in before querying, restricting each user to their assigned VRF views.
                      </p>
                    </div>
                  </div>
                </div>

                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    await api.updateSettings(boot.settings);
                    setAdminMsg('Global settings saved.');
                    await loadBootstrap();
                  }}
                  className="space-y-4 pt-5 border-t border-slate-800/40 text-xs"
                >
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Portal Title / Organization Name
                      </label>
                      <input
                        type="text"
                        value={boot.settings.organization_name}
                        onChange={(e) =>
                          setBoot({
                            ...boot,
                            settings: { ...boot.settings, organization_name: e.target.value },
                          })
                        }
                        className={`w-full px-3.5 py-2 rounded-lg border ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Primary ASN
                      </label>
                      <input
                        type="number"
                        value={boot.settings.primary_asn}
                        onChange={(e) =>
                          setBoot({
                            ...boot,
                            settings: {
                              ...boot.settings,
                              primary_asn: Number(e.target.value),
                            },
                          })
                        }
                        className={`w-full px-3.5 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Default PoP / Datacenter Code
                      </label>
                      <input
                        type="text"
                        value={boot.settings.datacenter_code}
                        onChange={(e) =>
                          setBoot({
                            ...boot,
                            settings: { ...boot.settings, datacenter_code: e.target.value },
                          })
                        }
                        className={`w-full px-3.5 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Admin URL Path (via config.yaml)
                      </label>
                      <input
                        type="text"
                        disabled
                        value={`/${boot.settings.admin_secret_slug || 'console'}`}
                        className={`w-full px-3.5 py-2 rounded-lg border font-mono opacity-75 ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Route Cache TTL (Seconds)
                      </label>
                      <input
                        type="number"
                        value={boot.settings.cache_ttl_seconds}
                        onChange={(e) =>
                          setBoot({
                            ...boot,
                            settings: {
                              ...boot.settings,
                              cache_ttl_seconds: Number(e.target.value),
                            },
                          })
                        }
                        className={`w-full px-3.5 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Default Rate Limit (Queries / Min)
                      </label>
                      <input
                        type="number"
                        value={boot.settings.rate_limit_per_minute}
                        onChange={(e) =>
                          setBoot({
                            ...boot,
                            settings: {
                              ...boot.settings,
                              rate_limit_per_minute: Number(e.target.value),
                            },
                          })
                        }
                        className={`w-full px-3.5 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                  </div>

                  <div>
                    <label className={`block font-medium mb-2 ${textSecondary}`}>
                      Permitted VRF / Routing Tables in Public Mode:
                    </label>
                    {boot.all_views.length === 0 ? (
                      <div className="text-slate-500 italic">
                        No VRF views configured yet. Add a VRF table in Section 2 first.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                        {boot.all_views.map((v) => {
                          const checked = boot.settings.public_allowed_views.includes(v.id);
                          return (
                            <label
                              key={v.id}
                              className={`flex items-center gap-2.5 p-3 rounded-xl border cursor-pointer ${bgSubCard}`}
                            >
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => {
                                  const cur = boot.settings.public_allowed_views;
                                  const next = checked
                                    ? cur.filter((x) => x !== v.id)
                                    : [...cur, v.id];
                                  setBoot({
                                    ...boot,
                                    settings: { ...boot.settings, public_allowed_views: next },
                                  });
                                }}
                              />
                              <span className={`font-semibold ${textPrimary}`}>{v.name}</span>
                              <span className="text-sky-500 font-mono text-[11px] ml-auto">
                                {v.vrf_name} ({v.pop && v.pop !== 'all' ? v.pop : 'ALL PoPs'})
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <button
                    type="submit"
                    className="px-5 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
                  >
                    Save Global Settings
                  </button>
                </form>
              </div>
            )}

            {/* SECTION 2: VRF / ROUTING TABLES (WITH POP DROPDOWN) */}
            {adminSection === 'views' && (
              <div className={`${bgCard} border rounded-2xl p-6 space-y-6 text-xs`}>
                <div>
                  <h2 className={`text-base font-bold ${textPrimary} mb-1`}>
                    VRF / Routing Table Management
                  </h2>
                  <p className={textSecondary}>
                    Configure Frontend Display Name (<b>Name</b>), Underlying RIB / VRF Name (
                    <b>VRF Name</b> — leave blank or enter <code className="text-sky-500">global</code>{' '}
                    for a single global table), Query Engine (<b>Type</b>), and <b>PoP Group Scope</b>.
                  </p>
                </div>

                {boot.all_views.length === 0 ? (
                  <div className={`p-6 rounded-xl border text-center ${bgSubCard} ${textSecondary}`}>
                    No VRF / Routing Table views configured yet. Use the form below to add your first routing table.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    {boot.all_views.map((v) => (
                      <div
                        key={v.id}
                        className={`p-4 rounded-xl border flex justify-between items-start gap-3 ${bgSubCard}`}
                      >
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`font-bold text-sm ${textPrimary}`}>{v.name}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-500 border border-emerald-500/30 font-mono uppercase font-semibold">
                              {v.type === 'gobgp' ? 'GOBGP (gRPC)' : v.type}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-sky-500/15 text-sky-500 border border-sky-500/30 font-mono">
                              PoP: {v.pop && v.pop !== 'all' ? v.pop : 'ALL PoPs'}
                            </span>
                          </div>
                          <div className="font-mono text-sky-500">
                            VRF Name: <span className={textPrimary}>{v.vrf_name}</span> · ID: {v.id}
                          </div>
                          {v.juniper_source_ipv4 && (
                            <div className={`font-mono ${textSecondary}`}>
                              Neighbor Peer IP: {v.juniper_source_ipv4}
                            </div>
                          )}
                          {v.description && <div className={textSecondary}>{v.description}</div>}
                        </div>
                        <div className="flex gap-1.5 shrink-0">
                          <button
                            onClick={() =>
                              setEditingView({
                                ...v,
                                vrf_name: v.vrf_name || v.junos_context_name || '',
                                type: v.type || 'gobgp',
                                pop: v.pop || 'all',
                              })
                            }
                            className="px-2.5 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-500 font-medium"
                          >
                            Edit
                          </button>
                          <button
                            onClick={async () => {
                              try {
                                await api.deleteRouteView(v.id);
                                setAdminMsg(`Deleted VRF table ${v.name}`);
                                await loadBootstrap();
                                await loadAdminData();
                              } catch (err: unknown) {
                                setAdminMsg(
                                  err instanceof Error ? err.message : 'Delete failed'
                                );
                              }
                            }}
                            className="px-2.5 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 font-medium"
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
                      const vrfVal = editingView.vrf_name.trim() || 'global';
                      const popVal = (editingView.pop || '').trim() || 'all';
                      const payload: RouteViewMeta = {
                        ...editingView,
                        vrf_name: vrfVal,
                        pop: popVal,
                        short_name: vrfVal === 'global' ? 'GLOBAL' : vrfVal,
                        junos_context_name: vrfVal,
                        junos_table: `${vrfVal}.inet.0`,
                        bird_table_v4: vrfVal,
                        frr_view_name: vrfVal,
                      };
                      await api.saveRouteView(payload);
                      setAdminMsg(
                        `Saved VRF table: ${editingView.name} (${vrfVal} · PoP: ${popVal})`
                      );
                      setEditingView({
                        id: '',
                        name: '',
                        vrf_name: '',
                        type: 'gobgp',
                        pop: 'all',
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
                      await loadBootstrap();
                      await loadAdminData();
                    } catch (err: unknown) {
                      setAdminMsg(err instanceof Error ? err.message : 'Save failed');
                    }
                  }}
                  className="pt-5 border-t border-slate-800/40 space-y-4"
                >
                  <h3 className={`text-sm font-bold ${textPrimary}`}>
                    Add or Update VRF / Routing Table
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-5 gap-3.5">
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        1. Display Name (Name) *
                      </label>
                      <input
                        type="text"
                        required
                        value={editingView.name}
                        onChange={(e) => setEditingView({ ...editingView, name: e.target.value })}
                        placeholder="e.g. CN Optimized Routing"
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        2. VRF Name <span className="text-sky-500">[Blank/global = Global]</span>
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
                        placeholder="e.g. VRF-CN-OPTIMIZE"
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        3. Engine Type (Type) *
                      </label>
                      <select
                        value={editingView.type || 'gobgp'}
                        onChange={(e) => setEditingView({ ...editingView, type: e.target.value })}
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      >
                        <option value="gobgp">gobgp (GoBGP gRPC)</option>
                        <option value="bird2">bird2 (BIRD 2 Table)</option>
                        <option value="frr">frr (FRR BGP View)</option>
                      </select>
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        4. PoP Group Scope
                      </label>
                      <select
                        value={editingView.pop || 'all'}
                        onChange={(e) => setEditingView({ ...editingView, pop: e.target.value })}
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      >
                        <option value="all">all (Available in All PoPs)</option>
                        {configuredPOPGroups.map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.name} ({p.id})
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        5. Neighbor Peer IPv4
                      </label>
                      <input
                        type="text"
                        value={editingView.juniper_source_ipv4}
                        onChange={(e) =>
                          setEditingView({ ...editingView, juniper_source_ipv4: e.target.value })
                        }
                        placeholder="e.g. 192.168.0.46"
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        Custom View ID (Optional)
                      </label>
                      <input
                        type="text"
                        value={editingView.id}
                        onChange={(e) => setEditingView({ ...editingView, id: e.target.value })}
                        placeholder="Auto-generated if blank"
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                    <div className="md:col-span-3">
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        Description
                      </label>
                      <input
                        type="text"
                        value={editingView.description}
                        onChange={(e) =>
                          setEditingView({ ...editingView, description: e.target.value })
                        }
                        placeholder="Optional description"
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
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
            )}

            {/* SECTION 3: POP GROUPS & MULTI-RR COLLECTOR NODES */}
            {adminSection === 'rr' && (
              <div className="space-y-6 text-xs">
                {/* STEP 1: DEFINE POP GROUPS */}
                <div className={`${bgCard} border rounded-2xl p-6 space-y-5`}>
                  <div>
                    <h2 className={`text-base font-bold ${textPrimary} mb-1`}>
                      Step 1: PoP Group Management (Define PoPs First)
                    </h2>
                    <p className={textSecondary}>
                      Define your Points of Presence (PoPs) as groups here first (e.g.,{' '}
                      <code className="text-sky-500">HKG-POP-01</code>,{' '}
                      <code className="text-sky-500">TYO-POP-01</code>,{' '}
                      <code className="text-sky-500">SGP-POP-01</code>). When adding Route Reflector
                      (RR) nodes below, select the corresponding PoP group from the dropdown. If 2
                      or more PoPs are active, the Public Looking Glass automatically displays PoP
                      tabs above the query type bar.
                    </p>
                  </div>

                  {configuredPOPGroups.length === 0 ? (
                    <div className={`p-4 rounded-xl border text-center ${bgSubCard} ${textSecondary}`}>
                      No PoP groups defined yet. Create your first PoP group below.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                      {configuredPOPGroups.map((pop) => (
                        <div
                          key={pop.id}
                          className={`p-3.5 rounded-xl border flex flex-col justify-between gap-2 ${bgSubCard}`}
                        >
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className={`font-bold text-sm ${textPrimary}`}>{pop.name}</span>
                              <span className="text-[10px] px-2 py-0.5 rounded bg-sky-500/15 text-sky-500 border border-sky-500/30 font-mono font-semibold">
                                {pop.id}
                              </span>
                            </div>
                            {pop.description && (
                              <div className={`mt-1 ${textSecondary}`}>{pop.description}</div>
                            )}
                          </div>
                          <div className="flex items-center gap-2 pt-2 border-t border-slate-800/30">
                            <button
                              type="button"
                              onClick={() => setEditingPOP(pop)}
                              className="text-sky-500 hover:underline font-medium"
                            >
                              Edit
                            </button>
                            <button
                              type="button"
                              onClick={async () => {
                                try {
                                  await api.deletePOP(pop.id);
                                  setAdminMsg(`Deleted PoP group ${pop.id}`);
                                  await loadBootstrap();
                                } catch (err: unknown) {
                                  setAdminMsg(
                                    err instanceof Error ? err.message : 'Delete failed'
                                  );
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
                        await loadBootstrap();
                      } catch (err: unknown) {
                        setAdminMsg(err instanceof Error ? err.message : 'Save PoP failed');
                      }
                    }}
                    className="grid grid-cols-1 md:grid-cols-4 gap-3.5 pt-4 border-t border-slate-800/40 items-end"
                  >
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        PoP Code / ID *
                      </label>
                      <input
                        type="text"
                        required
                        value={editingPOP.id}
                        onChange={(e) => setEditingPOP({ ...editingPOP, id: e.target.value })}
                        placeholder="e.g. HKG-POP-01"
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        PoP Display Name *
                      </label>
                      <input
                        type="text"
                        required
                        value={editingPOP.name}
                        onChange={(e) => setEditingPOP({ ...editingPOP, name: e.target.value })}
                        placeholder="e.g. Hong Kong POP"
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        Description (Optional)
                      </label>
                      <input
                        type="text"
                        value={editingPOP.description}
                        onChange={(e) =>
                          setEditingPOP({ ...editingPOP, description: e.target.value })
                        }
                        placeholder="e.g. Equinix HK1 / MEGA-i"
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
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

                {/* STEP 2: ROUTE REFLECTOR (RR) NODES ASSIGNED TO POP GROUPS */}
                <div className={`${bgCard} border rounded-2xl p-6 space-y-5`}>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 className={`text-base font-bold ${textPrimary} mb-1`}>
                        Step 2: Route Reflector (RR) Collector Nodes (Assigned by PoP Group)
                      </h2>
                      <p className={textSecondary}>
                        Assign each RR node to a defined PoP Group and configure 1 or multiple RRs (
                        <code className="text-sky-500">primary</code> +{' '}
                        <code className="text-amber-500">backup</code>) per PoP.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setEditingRR({
                          id: `rr-0${boot.rr_nodes.length + 1}`,
                          name: `LG-RR0${boot.rr_nodes.length + 1}`,
                          location:
                            configuredPOPGroups[0]?.id ||
                            boot.settings.datacenter_code ||
                            'HKG-POP-01',
                          engine_type: 'gobgp',
                          loopback_ip: '127.0.0.1',
                          endpoint: '127.0.0.1:50051',
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
                    <div className={`p-6 rounded-xl border text-center text-amber-500 ${bgSubCard}`}>
                      No Route Reflector (RR) node configured yet. Add at least 1 RR node below to enable BGP route queries.
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {Array.from(rrsByPOP.entries()).map(([popCode, popNodes]) => (
                        <div key={popCode} className={`p-4 rounded-xl border ${bgSubCard} space-y-3`}>
                          <div className="flex items-center justify-between border-b border-slate-800/40 pb-2">
                            <div className="flex items-center gap-2">
                              <span className="px-2.5 py-0.5 rounded-md bg-sky-500/15 text-sky-500 border border-sky-500/30 font-mono font-bold">
                                PoP: {popNameByID.get(popCode.toUpperCase()) || popCode} ({popCode})
                              </span>
                              <span className={textSecondary}>
                                ({popNodes.length} {popNodes.length === 1 ? 'RR Node' : 'RR Nodes'})
                              </span>
                            </div>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                            {popNodes.map((n) => (
                              <div
                                key={n.id}
                                className={`p-4 rounded-xl border flex flex-col justify-between gap-3 ${
                                  n.enabled ? bgCard : `${bgCard} opacity-60`
                                }`}
                              >
                                <div>
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className={`font-bold text-sm flex items-center gap-2 ${textPrimary}`}>
                                      <span>{n.name}</span>
                                      <span
                                        className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase ${
                                          n.role === 'primary'
                                            ? 'bg-sky-500/20 text-sky-500 border border-sky-500/30'
                                            : 'bg-amber-500/20 text-amber-500 border border-amber-500/30'
                                        }`}
                                      >
                                        {n.role}
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                      <span
                                        className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                                          n.enabled
                                            ? 'bg-emerald-500/20 text-emerald-500'
                                            : 'bg-rose-500/20 text-rose-500'
                                        }`}
                                      >
                                        {n.enabled ? 'ENABLED' : 'DISABLED'}
                                      </span>
                                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-500/15 text-slate-400 font-mono uppercase">
                                        {n.engine_type === 'gobgp' ? 'GOBGP (gRPC)' : n.engine_type}
                                      </span>
                                    </div>
                                  </div>
                                  <div className="font-mono text-sky-500 mt-2">
                                    Endpoint: <span className="text-emerald-500">{n.endpoint}</span> ·
                                    Loopback: {n.loopback_ip}
                                  </div>
                                  <div className={`font-mono mt-0.5 text-[11px] ${textSecondary}`}>
                                    ID: {n.id} · PoP: {n.location} · Status:{' '}
                                    <span className={n.healthy ? 'text-emerald-500' : 'text-amber-500'}>
                                      {n.healthy ? 'Reachable' : 'Unverified'}
                                    </span>
                                  </div>
                                </div>

                                <div className="flex flex-wrap items-center gap-2 pt-2.5 border-t border-slate-800/40">
                                  <button
                                    type="button"
                                    onClick={async () => {
                                      try {
                                        const res = await api.probeRRNode(n.id);
                                        setAdminMsg(
                                          `[Probe ${n.name}] ${res.reachable ? 'REACHABLE' : 'FAILED'}: ${res.message}`
                                        );
                                        await loadBootstrap();
                                        await loadAdminData();
                                      } catch (err: unknown) {
                                        setAdminMsg(
                                          err instanceof Error ? err.message : 'Probe failed'
                                        );
                                      }
                                    }}
                                    className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-500 border border-emerald-500/30 font-medium"
                                  >
                                    Test Connection
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => setEditingRR(n)}
                                    className="px-2.5 py-1 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-500 font-medium"
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
                                        await loadBootstrap();
                                      } catch (err: unknown) {
                                        setAdminMsg(
                                          err instanceof Error ? err.message : 'Update failed'
                                        );
                                      }
                                    }}
                                    className="px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-500 font-medium"
                                  >
                                    {n.enabled ? 'Disable' : 'Enable'}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={async () => {
                                      try {
                                        await api.deleteRRNode(n.id);
                                        setAdminMsg(`Deleted RR Node ${n.name}`);
                                        await loadBootstrap();
                                      } catch (err: unknown) {
                                        setAdminMsg(
                                          err instanceof Error ? err.message : 'Delete failed'
                                        );
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
                        await loadBootstrap();
                        await loadAdminData();
                      } catch (err: unknown) {
                        setAdminMsg(err instanceof Error ? err.message : 'Save failed');
                      }
                    }}
                    className="pt-5 border-t border-slate-800/40 space-y-3.5"
                  >
                    <h3 className={`text-sm font-bold ${textPrimary}`}>
                      Add or Update Route Reflector (RR) Node
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          1. Select PoP Group *
                        </label>
                        {configuredPOPGroups.length > 0 ? (
                          <select
                            value={editingRR.location || configuredPOPGroups[0].id}
                            onChange={(e) =>
                              setEditingRR({ ...editingRR, location: e.target.value })
                            }
                            className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
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
                            onChange={(e) =>
                              setEditingRR({ ...editingRR, location: e.target.value })
                            }
                            placeholder="Define a PoP in Step 1 above (e.g. HKG-POP-01)"
                            className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                          />
                        )}
                      </div>
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          2. RR Node Name *
                        </label>
                        <input
                          type="text"
                          required
                          value={editingRR.name}
                          onChange={(e) => setEditingRR({ ...editingRR, name: e.target.value })}
                          placeholder="e.g. LG-RR01"
                          className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                        />
                      </div>
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          3. RR Engine Type *
                        </label>
                        <select
                          value={editingRR.engine_type}
                          onChange={(e) => {
                            const nextEngine = e.target.value;
                            let nextEndpoint = editingRR.endpoint;
                            if (
                              nextEngine === 'gobgp' &&
                              (!nextEndpoint || nextEndpoint.startsWith('/'))
                            ) {
                              nextEndpoint = '127.0.0.1:50051';
                            } else if (
                              nextEngine === 'bird2' &&
                              (!nextEndpoint || nextEndpoint.includes(':'))
                            ) {
                              nextEndpoint = '/run/bird/bird.ctl';
                            } else if (
                              nextEngine === 'frr' &&
                              (!nextEndpoint || nextEndpoint.includes(':'))
                            ) {
                              nextEndpoint = '/run/frr';
                            }
                            setEditingRR({
                              ...editingRR,
                              engine_type: nextEngine,
                              endpoint: nextEndpoint,
                            });
                          }}
                          className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                        >
                          <option value="gobgp">gobgp (GoBGP Native gRPC)</option>
                          <option value="bird2">bird2 (BIRD 2 Control Socket)</option>
                          <option value="frr">frr (FRRouting vtysh JSON)</option>
                        </select>
                      </div>
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          4.{' '}
                          {editingRR.engine_type === 'gobgp'
                            ? 'GoBGP gRPC Endpoint (host:port) *'
                            : editingRR.engine_type === 'bird2'
                              ? 'BIRD 2 Control Socket Path *'
                              : 'FRR vtysh Socket Directory *'}
                        </label>
                        <input
                          type="text"
                          required
                          value={editingRR.endpoint}
                          onChange={(e) =>
                            setEditingRR({ ...editingRR, endpoint: e.target.value })
                          }
                          placeholder={
                            editingRR.engine_type === 'gobgp'
                              ? 'e.g. 127.0.0.1:50051'
                              : editingRR.engine_type === 'bird2'
                                ? 'e.g. /run/bird/bird.ctl'
                                : 'e.g. /run/frr'
                          }
                          className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5 items-end">
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          5. RR Loopback IP *
                        </label>
                        <input
                          type="text"
                          required
                          value={editingRR.loopback_ip}
                          onChange={(e) =>
                            setEditingRR({ ...editingRR, loopback_ip: e.target.value })
                          }
                          placeholder="e.g. 192.168.0.199"
                          className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                        />
                      </div>
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          6. Role in PoP *
                        </label>
                        <select
                          value={editingRR.role || 'primary'}
                          onChange={(e) => setEditingRR({ ...editingRR, role: e.target.value })}
                          className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                        >
                          <option value="primary">primary (Preferred RR in PoP)</option>
                          <option value="backup">backup (Failover RR in PoP)</option>
                        </select>
                      </div>
                      <div>
                        <label className={`block font-medium mb-1 ${textSecondary}`}>
                          7. Node ID (Auto if blank)
                        </label>
                        <input
                          type="text"
                          value={editingRR.id}
                          onChange={(e) => setEditingRR({ ...editingRR, id: e.target.value })}
                          placeholder="e.g. rr-01"
                          className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                        />
                      </div>
                      <div className="flex items-center gap-3">
                        <label
                          className={`flex items-center gap-1.5 cursor-pointer shrink-0 ${textPrimary}`}
                        >
                          <input
                            type="checkbox"
                            checked={editingRR.enabled !== false}
                            onChange={(e) =>
                              setEditingRR({ ...editingRR, enabled: e.target.checked })
                            }
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

                {/* Live BGP Neighbor Session Summary inside Admin Console */}
                <div className={`${bgCard} border rounded-2xl p-6 overflow-x-auto`}>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className={`text-sm font-bold ${textPrimary}`}>
                      Live iBGP Neighbor Session Summary (Admin Only)
                    </h3>
                    <button
                      type="button"
                      onClick={loadAdminData}
                      className="px-3 py-1 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-500 font-medium"
                    >
                      Refresh Peers
                    </button>
                  </div>
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className={`border-b border-slate-800/40 ${textSecondary}`}>
                        <th className="py-2.5 px-3">Route View</th>
                        <th className="py-2.5 px-3">VRF / Instance</th>
                        <th className="py-2.5 px-3">Neighbor IP</th>
                        <th className="py-2.5 px-3">Session State</th>
                        <th className="py-2.5 px-3">IPv4 Prefixes</th>
                        <th className="py-2.5 px-3">IPv6 Prefixes</th>
                        <th className="py-2.5 px-3">Uptime</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/30 font-mono">
                      {neighbors.length === 0 ? (
                        <tr>
                          <td colSpan={7} className={`py-4 text-center font-sans ${textSecondary}`}>
                            No neighbor sessions available.
                          </td>
                        </tr>
                      ) : (
                        neighbors.map((n) => (
                          <tr key={n.view_id}>
                            <td className={`py-2.5 px-3 font-sans font-semibold ${textPrimary}`}>
                              {n.view_name}
                            </td>
                            <td className="py-2.5 px-3 text-sky-500">{n.junos_context}</td>
                            <td className="py-2.5 px-3 text-amber-500">{n.neighbor_ip || '-'}</td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[11px] ${
                                  n.session_state === 'Established'
                                    ? 'bg-emerald-500/20 text-emerald-500'
                                    : 'bg-rose-500/20 text-rose-500'
                                }`}
                              >
                                {n.session_state}
                              </span>
                            </td>
                            <td className={`py-2.5 px-3 ${textPrimary}`}>
                              {n.prefixes_ipv4.toLocaleString()}
                            </td>
                            <td className={`py-2.5 px-3 ${textPrimary}`}>
                              {n.prefixes_ipv6.toLocaleString()}
                            </td>
                            <td className={`py-2.5 px-3 ${textSecondary}`}>{n.uptime}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* SECTION 4: USER ACCOUNTS & RBAC */}
            {adminSection === 'users' && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 text-xs">
                <div className={`lg:col-span-5 ${bgCard} border rounded-2xl p-6`}>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className={`text-sm font-bold ${textPrimary}`}>
                      {editingUser.id ? `Edit Account: ${editingUser.username}` : 'Create Account'}
                    </h3>
                    {editingUser.id && (
                      <button
                        type="button"
                        onClick={() =>
                          setEditingUser({
                            username: '',
                            password: '',
                            display_name: '',
                            company: '',
                            customer_asn: 0,
                            role: 'customer',
                            allowed_views: boot.all_views.map((v) => v.id),
                            rate_limit_per_minute: 60,
                            enabled: true,
                            must_change_password: true,
                            notes: '',
                          })
                        }
                        className="text-sky-500 hover:underline text-[11px] font-medium"
                      >
                        + New Account
                      </button>
                    )}
                  </div>
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      try {
                        await api.saveUser(editingUser);
                        setAdminMsg(`Saved account ${editingUser.username}`);
                        setEditingUser({
                          username: '',
                          password: '',
                          display_name: '',
                          company: '',
                          customer_asn: 0,
                          role: 'customer',
                          allowed_views: boot.all_views.map((v) => v.id),
                          rate_limit_per_minute: 60,
                          enabled: true,
                          must_change_password: true,
                          notes: '',
                        });
                        await loadBootstrap();
                        await loadAdminData();
                      } catch (err: unknown) {
                        setAdminMsg(err instanceof Error ? err.message : 'Save failed');
                      }
                    }}
                    className="space-y-3.5"
                  >
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>Username *</label>
                      <input
                        type="text"
                        required
                        value={editingUser.username}
                        onChange={(e) =>
                          setEditingUser({ ...editingUser, username: e.target.value })
                        }
                        className={`w-full px-3 py-2 rounded-lg border font-mono ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        Password {editingUser.id ? '(Leave blank to keep existing)' : '*'}
                      </label>
                      <input
                        type="password"
                        required={!editingUser.id}
                        value={editingUser.password}
                        onChange={(e) =>
                          setEditingUser({ ...editingUser, password: e.target.value })
                        }
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>
                        Display Name / Organization
                      </label>
                      <input
                        type="text"
                        value={editingUser.display_name}
                        onChange={(e) =>
                          setEditingUser({
                            ...editingUser,
                            display_name: e.target.value,
                            company: e.target.value,
                          })
                        }
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                      />
                    </div>
                    <div>
                      <label className={`block font-medium mb-1 ${textSecondary}`}>Role</label>
                      <select
                        value={editingUser.role}
                        onChange={(e) =>
                          setEditingUser({
                            ...editingUser,
                            role: e.target.value as 'admin' | 'noc' | 'customer',
                          })
                        }
                        className={`w-full px-3 py-2 rounded-lg border ${bgInput}`}
                      >
                        <option value="customer">Customer (Restricted to Selected VRFs)</option>
                        <option value="noc">NOC Engineer</option>
                        <option value="admin">Administrator (Full Access)</option>
                      </select>
                    </div>

                    <div className="pt-1">
                      <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-500 cursor-pointer font-medium">
                        <input
                          type="checkbox"
                          checked={editingUser.must_change_password}
                          onChange={(e) =>
                            setEditingUser({
                              ...editingUser,
                              must_change_password: e.target.checked,
                            })
                          }
                        />
                        <span>Require password change on first / next login</span>
                      </label>
                    </div>

                    <div>
                      <label className={`block font-medium mb-1.5 ${textSecondary}`}>
                        Authorized BGP VRF Views:
                      </label>
                      {boot.all_views.length === 0 ? (
                        <div className="text-slate-500 italic">No VRF views configured.</div>
                      ) : (
                        <div className="space-y-1.5">
                          {boot.all_views.map((v) => {
                            const checked =
                              editingUser.role === 'admin' ||
                              editingUser.allowed_views.includes(v.id);
                            return (
                              <label
                                key={v.id}
                                className={`flex items-center gap-2 p-2.5 rounded-lg border cursor-pointer ${bgSubCard}`}
                              >
                                <input
                                  type="checkbox"
                                  disabled={editingUser.role === 'admin'}
                                  checked={checked}
                                  onChange={() => {
                                    const cur = editingUser.allowed_views;
                                    const next = checked
                                      ? cur.filter((x) => x !== v.id)
                                      : [...cur, v.id];
                                    setEditingUser({ ...editingUser, allowed_views: next });
                                  }}
                                />
                                <span className={`font-semibold ${textPrimary}`}>{v.name}</span>
                                <span className="text-sky-500 font-mono text-[11px] ml-auto">
                                  {v.vrf_name}
                                </span>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    <button
                      type="submit"
                      className="w-full py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
                    >
                      Save Account
                    </button>
                  </form>
                </div>

                <div className={`lg:col-span-7 ${bgCard} border rounded-2xl p-6 overflow-x-auto`}>
                  <h3 className={`text-sm font-bold ${textPrimary} mb-4`}>
                    Configured Accounts ({users.length})
                  </h3>
                  <table className="w-full text-left">
                    <thead>
                      <tr className={`border-b border-slate-800/40 ${textSecondary}`}>
                        <th className="py-2.5 px-2">Username / Organization</th>
                        <th className="py-2.5 px-2">Role</th>
                        <th className="py-2.5 px-2">Authorized VRF Views</th>
                        <th className="py-2.5 px-2">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/30">
                      {users.map((u) => {
                        const activeViews =
                          u.role === 'admin'
                            ? boot.all_views
                            : (u.allowed_views || [])
                                .map((vid) => viewByID.get(vid))
                                .filter((v): v is RouteViewMeta => !!v);
                        return (
                          <tr key={u.id}>
                            <td className="py-3 px-2">
                              <div className="flex items-center gap-2">
                                <span className={`font-bold ${textPrimary}`}>{u.username}</span>
                                {u.must_change_password && (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-500 border border-amber-500/30 font-mono">
                                    Pwd Reset Required
                                  </span>
                                )}
                              </div>
                              <div className={textSecondary}>{u.display_name}</div>
                            </td>
                            <td className="py-3 px-2 font-mono uppercase text-sky-500 font-semibold">
                              {u.role}
                            </td>
                            <td className="py-3 px-2">
                              {activeViews.length === 0 ? (
                                <span className="text-slate-500 italic">None</span>
                              ) : (
                                <div className="flex flex-wrap gap-1.5">
                                  {activeViews.map((v) => (
                                    <span
                                      key={v.id}
                                      className="px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 font-mono text-[11px]"
                                      title={`ID: ${v.id}`}
                                    >
                                      {v.vrf_name} ({v.name})
                                    </span>
                                  ))}
                                </div>
                              )}
                            </td>
                            <td className="py-3 px-2 space-x-2.5 whitespace-nowrap">
                              <button
                                onClick={() =>
                                  setEditingUser({
                                    id: u.id,
                                    username: u.username,
                                    password: '',
                                    display_name: u.display_name,
                                    company: u.company,
                                    customer_asn: u.customer_asn || 0,
                                    role: u.role,
                                    allowed_views: activeViews.map((v) => v.id),
                                    rate_limit_per_minute: u.rate_limit_per_minute,
                                    enabled: u.enabled,
                                    must_change_password: !!u.must_change_password,
                                    notes: u.notes || '',
                                  })
                                }
                                className="text-sky-500 hover:underline font-medium"
                              >
                                Edit
                              </button>
                              {u.username !== 'admin' && (
                                <button
                                  onClick={async () => {
                                    await api.deleteUser(u.id);
                                    await loadAdminData();
                                  }}
                                  className="text-rose-500 hover:underline font-medium"
                                >
                                  Delete
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* SECTION 5: COMMUNITY DICTIONARY CRUD (ADMIN ONLY) */}
            {adminSection === 'communities' && (
              <div className={`${bgCard} border rounded-2xl p-6 space-y-5 text-xs`}>
                <div>
                  <h2 className={`text-base font-bold ${textPrimary} mb-1`}>
                    BGP Community Translation Dictionary
                  </h2>
                  <p className={textSecondary}>
                    Maintain internal or carrier BGP community labels for administrative reference.
                  </p>
                </div>
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                      await api.saveCommunity(editingComm);
                      setAdminMsg(`Saved Community ${editingComm.community}`);
                      setEditingComm({
                        community: '',
                        label: '',
                        category: 'upstream',
                        description: '',
                      });
                      await loadBootstrap();
                    } catch (err: unknown) {
                      setAdminMsg(err instanceof Error ? err.message : 'Save failed');
                    }
                  }}
                  className="grid grid-cols-1 md:grid-cols-4 gap-3.5"
                >
                  <input
                    type="text"
                    required
                    value={editingComm.community}
                    onChange={(e) => setEditingComm({ ...editingComm, community: e.target.value })}
                    placeholder="Community (e.g. 65000:1001)"
                    className={`px-3.5 py-2 rounded-lg border font-mono ${bgInput}`}
                  />
                  <input
                    type="text"
                    required
                    value={editingComm.label}
                    onChange={(e) => setEditingComm({ ...editingComm, label: e.target.value })}
                    placeholder="Label"
                    className={`px-3.5 py-2 rounded-lg border ${bgInput}`}
                  />
                  <input
                    type="text"
                    value={editingComm.description}
                    onChange={(e) =>
                      setEditingComm({ ...editingComm, description: e.target.value })
                    }
                    placeholder="Description"
                    className={`px-3.5 py-2 rounded-lg border ${bgInput}`}
                  />
                  <button
                    type="submit"
                    className="py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
                  >
                    Save Community
                  </button>
                </form>

                {boot.communities.length === 0 ? (
                  <div className={`p-6 rounded-xl border text-center ${bgSubCard} ${textSecondary}`}>
                    No BGP community entries configured.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-4 border-t border-slate-800/40">
                    {boot.communities.map((c) => (
                      <div
                        key={c.community}
                        className={`p-3.5 rounded-xl border flex justify-between items-center ${bgSubCard}`}
                      >
                        <div>
                          <span className="font-mono font-bold text-sky-500">{c.community}</span> —{' '}
                          <span className={`font-semibold ${textPrimary}`}>{c.label}</span>
                          {c.description && (
                            <div className={`${textSecondary} mt-0.5`}>{c.description}</div>
                          )}
                        </div>
                        <button
                          onClick={async () => {
                            await api.deleteCommunity(c.community);
                            await loadBootstrap();
                          }}
                          className="text-rose-500 hover:underline shrink-0 ml-2 font-medium"
                        >
                          Delete
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* SECTION 6: AUDIT LOGS & CACHE (WITH PAGINATION & PAGE SIZE) */}
            {adminSection === 'logs' && (() => {
              const totalLogs = auditLogs.length;
              const totalPages = Math.max(1, Math.ceil(totalLogs / auditPageSize));
              const currentPage = Math.min(Math.max(1, auditPage), totalPages);
              const startIdx = (currentPage - 1) * auditPageSize;
              const pagedLogs = auditLogs.slice(startIdx, startIdx + auditPageSize);

              return (
                <div className={`${bgCard} border rounded-2xl p-6 space-y-4 text-xs`}>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className={`text-base font-bold ${textPrimary}`}>
                        Query & Administrative Audit Logs
                      </h2>
                      <p className={`text-[11px] ${textSecondary} mt-0.5`}>
                        {totalLogs === 0
                          ? 'No audit log entries recorded yet.'
                          : `Showing ${startIdx + 1}–${Math.min(startIdx + auditPageSize, totalLogs)} of ${totalLogs} entries`}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className={textSecondary}>Rows per page:</span>
                        <select
                          value={auditPageSize}
                          onChange={(e) => {
                            setAuditPageSize(Number(e.target.value));
                            setAuditPage(1);
                          }}
                          className={`px-2.5 py-1.5 rounded-lg border font-mono ${bgInput}`}
                        >
                          <option value={10}>10</option>
                          <option value={20}>20</option>
                          <option value={50}>50</option>
                          <option value={100}>100</option>
                        </select>
                      </div>

                      <button
                        type="button"
                        onClick={loadAdminData}
                        className="px-3 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-500 border border-sky-500/30 font-semibold transition"
                      >
                        Refresh Logs
                      </button>

                      <button
                        type="button"
                        onClick={async () => {
                          await api.clearCache();
                          setAdminMsg('Flushed all cached BGP query results.');
                          await loadAdminData();
                        }}
                        className="px-3.5 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-500 border border-amber-500/30 font-semibold transition"
                      >
                        Flush Route Cache
                      </button>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono">
                      <thead>
                        <tr className={`border-b border-slate-800/40 ${textSecondary}`}>
                          <th className="py-2.5 px-2">Time</th>
                          <th className="py-2.5 px-2">User</th>
                          <th className="py-2.5 px-2">Client IP</th>
                          <th className="py-2.5 px-2">Action</th>
                          <th className="py-2.5 px-2">Query Target / Views</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/30">
                        {pagedLogs.length === 0 ? (
                          <tr>
                            <td colSpan={5} className={`py-6 text-center font-sans ${textSecondary}`}>
                              No audit log entries available.
                            </td>
                          </tr>
                        ) : (
                          pagedLogs.map((log, i) => (
                            <tr key={startIdx + i}>
                              <td className={`py-2.5 px-2 whitespace-nowrap ${textSecondary}`}>
                                {new Date(log.timestamp).toLocaleString()}
                              </td>
                              <td className={`py-2.5 px-2 ${textPrimary}`}>{log.username}</td>
                              <td className="py-2.5 px-2 text-sky-500">{log.client_ip}</td>
                              <td className="py-2.5 px-2 text-emerald-500">{log.action}</td>
                              <td className={`py-2.5 px-2 ${textSecondary}`}>
                                {log.target
                                  ? `${log.query_type}: ${log.target} [${log.views}]`
                                  : '-'}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination Footer */}
                  {totalLogs > 0 && (
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/40">
                      <div className={`font-mono ${textSecondary}`}>
                        Page <span className={`font-bold ${textPrimary}`}>{currentPage}</span> of{' '}
                        <span className={`font-bold ${textPrimary}`}>{totalPages}</span> ({totalLogs}{' '}
                        total logs)
                      </div>

                      <div className="flex items-center gap-1.5 font-mono">
                        <button
                          type="button"
                          disabled={currentPage <= 1}
                          onClick={() => setAuditPage(1)}
                          className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${bgSubCard} ${textPrimary}`}
                        >
                          « First
                        </button>
                        <button
                          type="button"
                          disabled={currentPage <= 1}
                          onClick={() => setAuditPage((p) => Math.max(1, p - 1))}
                          className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${bgSubCard} ${textPrimary}`}
                        >
                          ‹ Prev
                        </button>
                        <button
                          type="button"
                          disabled={currentPage >= totalPages}
                          onClick={() => setAuditPage((p) => Math.min(totalPages, p + 1))}
                          className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${bgSubCard} ${textPrimary}`}
                        >
                          Next ›
                        </button>
                        <button
                          type="button"
                          disabled={currentPage >= totalPages}
                          onClick={() => setAuditPage(totalPages)}
                          className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${bgSubCard} ${textPrimary}`}
                        >
                          Last »
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </section>
        </div>
      </div>
    );
  }

  // ============================================================================
  // PORTAL 1: PUBLIC / CUSTOMER BGP LOOKING GLASS PORTAL (/)
  // - Ultra-Wide Fluid Container (`max-w-[96vw]`) with Slim Margins
  // - Light / Dark / System Auto Theme Switcher (`☀ Light` | `🌙 Dark` | `💻 Auto`)
  // - PoP Segmented Tabs ABOVE Query Type Tabs (Hidden automatically if <= 1 PoP)
  // - ZERO Admin Console / Login Buttons in Public Mode (Admin only via /<admin_path>)
  // ============================================================================
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

  return (
    <div className={`min-h-screen ${bgPage} flex flex-col font-sans transition-colors duration-150`}>
      {mustChangePasswordGate &&
        renderPasswordChangeModal(!!boot.current_user?.must_change_password)}

      <header className={`border-b ${bgHeader} backdrop-blur sticky top-0 z-30`}>
        <div className={`${layoutContainer} py-3.5 flex flex-wrap items-center justify-between gap-4`}>
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center font-bold text-sm text-white shadow-lg shadow-sky-500/20">
              BGP
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <span className={`font-bold text-base tracking-tight ${textPrimary}`}>
                  {boot.settings.organization_name}
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded-md bg-sky-500/15 text-sky-500 border border-sky-500/30 font-mono font-semibold">
                  AS{boot.settings.primary_asn}
                </span>
                <span
                  className={`text-[11px] px-2 py-0.5 rounded-md border font-mono ${
                    isDark
                      ? 'bg-slate-800/90 text-slate-300 border-slate-700/80'
                      : 'bg-slate-100 text-slate-700 border-slate-300'
                  }`}
                >
                  {activePOPDisplay}
                </span>
              </div>
              <p className={`text-xs ${textSecondary} mt-0.5`}>
                Carrier-Grade Real-Time BGP Routing Table Looking Glass
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            {renderThemeSwitcher()}

            {/* Only display account controls when the portal is in auth_required mode */}
            {isAuthRequiredMode && boot.current_user && (
              <div
                className={`flex items-center gap-2.5 border rounded-xl px-3.5 py-1.5 ${bgSubCard}`}
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className={`font-semibold ${textPrimary}`}>
                  {boot.current_user.display_name || boot.current_user.username}
                </span>
                <button
                  onClick={() => {
                    setPwdError('');
                    setShowChangePwdModal(true);
                  }}
                  className="text-sky-500 hover:underline ml-1 font-medium"
                >
                  Password
                </button>
                <button
                  onClick={handleLogout}
                  className="text-rose-500 hover:underline ml-1 font-medium"
                >
                  Sign Out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className={`${layoutContainer} py-6 flex-1`}>
        {requiresCustomerLoginGate ? (
          <div className={`max-w-md mx-auto mt-12 ${bgCard} border rounded-2xl p-7`}>
            <h2 className={`text-base font-bold ${textPrimary} mb-1`}>
              Sign In Required — {boot.settings.organization_name}
            </h2>
            <p className={`text-xs ${textSecondary} mb-5`}>
              Please sign in with your authorized account to query BGP routing tables.
            </p>
            {loginError && (
              <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                {loginError}
              </div>
            )}
            <form onSubmit={(e) => handleLogin(e)} className="space-y-4">
              <div>
                <label className={`block text-xs font-medium ${textSecondary} mb-1.5`}>
                  Username
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${bgInput} focus:outline-none focus:border-sky-500`}
                />
              </div>
              <div>
                <label className={`block text-xs font-medium ${textSecondary} mb-1.5`}>
                  Password
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${bgInput} focus:outline-none focus:border-sky-500`}
                />
              </div>
              <button
                type="submit"
                className="w-full py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold text-sm transition shadow-lg shadow-sky-600/20"
              >
                Sign In
              </button>
            </form>
          </div>
        ) : (
          <div className="space-y-5">
            {/* UNIFIED QUERY COMMAND PANEL */}
            <div className={`${bgCard} border rounded-2xl p-5 sm:p-6 space-y-4`}>
              {/* ROW 1 (OPTIONAL): MULTI-POP SEGMENTED TABS — ONLY SHOWN WHEN 2 OR MORE POPS ARE CONFIGURED */}
              {activePOPGroups.length > 1 && (
                <div className="flex flex-wrap items-center gap-2 pb-3 border-b border-slate-800/40">
                  <span className={`text-xs font-semibold mr-1 ${textSecondary}`}>PoP Node:</span>
                  <div
                    className={`inline-flex flex-wrap p-1 rounded-xl border gap-1 ${
                      isDark ? 'bg-[#060911] border-slate-800/90' : 'bg-slate-100 border-slate-200'
                    }`}
                  >
                    {activePOPGroups.map((pop) => {
                      const active = selectedPOP.toLowerCase() === pop.id.toLowerCase();
                      return (
                        <button
                          key={pop.id}
                          type="button"
                          onClick={() => {
                            if (selectedPOP.toLowerCase() !== pop.id.toLowerCase()) {
                              setSelectedPOP(pop.id);
                              setTarget('');
                              setLookupResult(null);
                              setLookupError('');
                            }
                          }}
                          className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 ${
                            active
                              ? 'bg-indigo-600 text-white shadow-sm'
                              : isDark
                                ? 'text-slate-400 hover:text-slate-200'
                                : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <span>{pop.name}</span>
                          {pop.name !== pop.id && (
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                                active
                                  ? 'bg-white/20 text-white'
                                  : isDark
                                    ? 'bg-slate-800 text-slate-400'
                                    : 'bg-slate-200 text-slate-600'
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

              {/* ROW 2: QUERY TYPE SEGMENTED TABS */}
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div
                  className={`inline-flex flex-wrap p-1 rounded-xl border gap-1 ${
                    isDark ? 'bg-[#060911] border-slate-800/90' : 'bg-slate-100 border-slate-200'
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
                      onClick={() => {
                        if (queryType !== qt.id) {
                          setQueryType(qt.id);
                          setTarget('');
                          setLookupResult(null);
                          setLookupError('');
                        }
                      }}
                      className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition ${
                        queryType === qt.id
                          ? 'bg-sky-600 text-white shadow-sm'
                          : isDark
                            ? 'text-slate-400 hover:text-slate-200'
                            : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {qt.label}
                    </button>
                  ))}
                </div>

                {visiblePermittedViews.length > 1 && (
                  <div className="flex items-center gap-3 text-xs">
                    <button
                      type="button"
                      onClick={() => setSelectedViews(visiblePermittedViews.map((v) => v.id))}
                      className="text-sky-500 hover:underline font-medium"
                    >
                      Select All ({visiblePermittedViews.length})
                    </button>
                    <span className={textSecondary}>|</span>
                    <button
                      type="button"
                      onClick={() => setSelectedViews([])}
                      className={`${textSecondary} hover:underline`}
                    >
                      Clear
                    </button>
                  </div>
                )}
              </div>

              {/* ROUTING INSTANCE / VRF PILLS */}
              <div>
                <div className={`text-xs font-medium ${textSecondary} mb-2`}>
                  Routing Instances / VRF Tables:
                </div>
                {visiblePermittedViews.length === 0 ? (
                  <div className={`p-4 rounded-xl border text-xs ${bgSubCard} ${textSecondary}`}>
                    No routing tables are currently assigned or configured.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-2.5">
                    {visiblePermittedViews.map((view) => {
                      const checked = selectedViews.includes(view.id);
                      return (
                        <button
                          key={view.id}
                          type="button"
                          onClick={() => toggleViewSelection(view.id)}
                          className={`group flex items-center gap-2.5 px-3.5 py-2 rounded-xl border text-xs transition ${
                            checked
                              ? isDark
                                ? 'bg-sky-500/15 border-sky-500/60 text-white shadow-sm'
                                : 'bg-sky-50 border-sky-500 text-sky-950 shadow-sm'
                              : `${bgSubCard} ${textSecondary} hover:opacity-90`
                          }`}
                        >
                          <span
                            className={`w-3.5 h-3.5 rounded flex items-center justify-center border text-[10px] ${
                              checked
                                ? 'bg-sky-500 border-sky-400 text-white font-bold'
                                : 'border-slate-500/50 bg-transparent'
                            }`}
                          >
                            {checked ? '✓' : ''}
                          </span>
                          <span className="font-semibold">{view.name}</span>
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase ${
                              isDark
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

              {/* SEARCH BAR */}
              <form
                onSubmit={(e) => handleRunLookup(e)}
                className="flex flex-col sm:flex-row gap-3"
              >
                <div className="relative flex-1">
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder={
                      queryType === 'prefix'
                        ? 'Enter IPv4/IPv6 address or CIDR prefix (e.g. 202.96.134.133 or 202.96.128.0/18)'
                        : queryType === 'aspath'
                          ? 'Enter ASN or AS-Path sequence (e.g. 4134 or 23764 4134)'
                          : 'Enter BGP Community or Extended Community (e.g. 23764:11100 or 58453:33960)'
                    }
                    className={`w-full px-4 py-3 rounded-xl border text-sm font-mono ${bgInput} focus:outline-none focus:border-sky-500 transition`}
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
                <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-500 text-xs font-mono">
                  {lookupError}
                </div>
              )}
            </div>

            {/* TERMINAL CLI OUTPUT WINDOWS (PURE CLI OUTPUT ONLY) */}
            {lookupResult && (
              <div className="space-y-5">
                {lookupResult.results.map((viewRes: ViewQueryResult) => (
                  <div
                    key={viewRes.view.id}
                    className={`border rounded-2xl overflow-hidden shadow-xl ${
                      isDark ? 'bg-[#070a12] border-slate-800/90' : 'bg-slate-900 border-slate-300'
                    }`}
                  >
                    <div
                      className={`px-5 py-3 border-b flex flex-wrap items-center justify-between gap-3 ${
                        isDark
                          ? 'bg-[#0c1220] border-slate-800/90'
                          : 'bg-slate-800 border-slate-700'
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2.5">
                        <div className="flex items-center gap-1.5 mr-1">
                          <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                        </div>
                        <span className="font-bold text-sm text-white">{viewRes.view.name}</span>
                        <span className="text-[11px] px-2 py-0.5 rounded-md bg-sky-500/20 text-sky-300 border border-sky-500/30 font-mono">
                          {viewRes.view.vrf_name}
                        </span>
                        <span className="text-[11px] px-2 py-0.5 rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
                          Matched: {viewRes.matched_prefix}
                        </span>
                        <span className="text-xs text-slate-300 font-mono">
                          {viewRes.total_paths} {viewRes.total_paths === 1 ? 'Path' : 'Paths'} ·{' '}
                          {viewRes.query_time_ms}ms
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() => copyCLIOutput(viewRes.view.id, viewRes.raw_output)}
                        className="px-3 py-1 rounded-lg bg-slate-950/80 hover:bg-slate-950 text-xs font-mono text-slate-200 border border-slate-700 transition"
                      >
                        {copiedViewID === viewRes.view.id ? '✓ Copied' : 'Copy Output'}
                      </button>
                    </div>

                    <pre className="p-5 text-xs font-mono text-emerald-300 bg-[#050811] whitespace-pre-wrap break-words leading-6 selection:bg-sky-500/30">
                      {viewRes.raw_output}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
};
