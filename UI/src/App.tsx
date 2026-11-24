// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api, setToken } from './api';
import { NotFoundView } from './components/common/NotFoundView';
import { PasswordChangeModal } from './components/common/PasswordChangeModal';
import { AdminPortal } from './features/admin/AdminPortal';
import { LookingGlassPortal } from './features/lg/LookingGlassPortal';
import { usePortalMeta } from './hooks/usePortalMeta';
import { useTheme } from './hooks/useTheme';
import { BootstrapResponse } from './types';
import {
  computeActivePOPGroups,
  computeConfiguredPOPGroups,
  getCurrentEntrySlug,
} from './utils/topology';

export const App: React.FC = () => {
  const [portalMode, setPortalMode] = useState<'lg' | 'admin' | 'notfound'>('lg');
  const [boot, setBoot] = useState<BootstrapResponse | null>(null);
  const [loadingBoot, setLoadingBoot] = useState(true);
  const [showChangePwdModal, setShowChangePwdModal] = useState(false);
  const [adminMsg, setAdminMsg] = useState('');

  const { themeMode, setThemeMode, ui } = useTheme();
  usePortalMeta(boot, portalMode);

  const loadBootstrap = useCallback(async () => {
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
  }, []);

  useEffect(() => {
    const onPopState = () => {
      loadBootstrap();
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [loadBootstrap]);

  useEffect(() => {
    loadBootstrap();
  }, [loadBootstrap]);

  const switchPortal = useCallback(
    (mode: 'lg' | 'admin', customSlug?: string) => {
      setPortalMode(mode);
      setAdminMsg('');
      if (mode === 'admin') {
        const slug = customSlug || boot?.settings.admin_secret_slug || getCurrentEntrySlug();
        if (slug) {
          window.history.pushState({}, '', `/${slug.replace(/^\/+/, '')}`);
        }
      } else {
        window.history.pushState({}, '', '/');
      }
    },
    [boot?.settings.admin_secret_slug]
  );

  const handleLogin = useCallback(
    async (username: string, password: string, targetPortal?: 'lg' | 'admin') => {
      const res = await api.login(username, password);
      setToken(res.token);
      if (targetPortal) {
        switchPortal(targetPortal);
      }
      await loadBootstrap();
    },
    [loadBootstrap, switchPortal]
  );

  const handleLogout = useCallback(async () => {
    setToken(null);
    setShowChangePwdModal(false);
    await loadBootstrap();
  }, [loadBootstrap]);

  const handleSubmitPasswordChange = useCallback(
    async (currentPassword: string, newPassword: string) => {
      const res = await api.changePassword(currentPassword, newPassword);
      setToken(res.token);
      setShowChangePwdModal(false);
      setAdminMsg('Password updated successfully.');
      await loadBootstrap();
    },
    [loadBootstrap]
  );

  const configuredPOPGroups = useMemo(() => computeConfiguredPOPGroups(boot), [boot]);
  const activePOPGroups = useMemo(
    () => computeActivePOPGroups(boot, configuredPOPGroups),
    [boot, configuredPOPGroups]
  );

  if (loadingBoot || !boot) {
    return (
      <div className={`min-h-screen ${ui.bgPage} flex items-center justify-center`}>
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 rounded-full border-2 border-sky-500 border-t-transparent animate-spin" />
          <div className={`text-sm font-medium ${ui.textSecondary}`}>
            Initializing BGP Looking Glass...
          </div>
        </div>
      </div>
    );
  }

  if (portalMode === 'notfound') {
    return <NotFoundView ui={ui} onReturnToLG={() => switchPortal('lg')} />;
  }

  const isMandatoryPasswordChange =
    !!boot.current_user?.must_change_password &&
    (portalMode === 'admin' || boot.settings.access_mode === 'auth_required');
  const mustShowPasswordModal = isMandatoryPasswordChange || showChangePwdModal;

  return (
    <>
      {mustShowPasswordModal && boot.current_user && (
        <PasswordChangeModal
          ui={ui}
          username={boot.current_user.username}
          isMandatory={isMandatoryPasswordChange}
          onClose={() => setShowChangePwdModal(false)}
          onLogout={handleLogout}
          onSubmitPasswordChange={handleSubmitPasswordChange}
        />
      )}

      {portalMode === 'admin' ? (
        <AdminPortal
          boot={boot}
          setBoot={setBoot}
          ui={ui}
          themeMode={themeMode}
          setThemeMode={setThemeMode}
          configuredPOPGroups={configuredPOPGroups}
          adminMsg={adminMsg}
          setAdminMsg={setAdminMsg}
          onLogin={(u, p) => handleLogin(u, p, 'admin')}
          onLogout={handleLogout}
          onSwitchToLG={() => switchPortal('lg')}
          onOpenPasswordModal={() => setShowChangePwdModal(true)}
          reloadBootstrap={loadBootstrap}
        />
      ) : (
        <LookingGlassPortal
          boot={boot}
          ui={ui}
          themeMode={themeMode}
          setThemeMode={setThemeMode}
          activePOPGroups={activePOPGroups}
          onLogin={(u, p) => handleLogin(u, p)}
          onLogout={handleLogout}
          onOpenPasswordModal={() => setShowChangePwdModal(true)}
        />
      )}
    </>
  );
};
