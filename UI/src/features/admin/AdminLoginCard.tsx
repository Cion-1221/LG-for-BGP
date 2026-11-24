// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { Footer } from '../../components/common/Footer';
import { ThemeSwitcher } from '../../components/common/ThemeSwitcher';
import { ThemeTokens } from '../../hooks/useTheme';
import { ThemeMode } from '../../types';

interface AdminLoginCardProps {
  ui: ThemeTokens;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  onLogin: (username: string, password: string) => Promise<void>;
}

export const AdminLoginCard: React.FC<AdminLoginCardProps> = ({
  ui,
  themeMode,
  setThemeMode,
  onLogin,
}) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      setLoading(true);
      await onLogin(username.trim(), password);
      setPassword('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`min-h-screen ${ui.bgPage} flex flex-col`}>
      <div className="flex-1 flex flex-col justify-center items-center p-4">
        <div className={`max-w-md w-full ${ui.bgCard} border rounded-2xl p-7`}>
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 text-slate-950 font-bold flex items-center justify-center text-sm shadow-lg shadow-amber-500/20">
                ADM
              </div>
              <div>
                <h1 className={`text-base font-bold ${ui.textPrimary}`}>Administration Console</h1>
                <p className={`text-xs ${ui.textSecondary}`}>BGP Looking Glass Control Plane</p>
              </div>
            </div>
            <ThemeSwitcher themeMode={themeMode} setThemeMode={setThemeMode} isDark={ui.isDark} />
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 dark:bg-rose-500/10 dark:border-rose-500/30 dark:text-rose-400 text-xs">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className={`block text-xs font-medium ${ui.textSecondary} mb-1.5`}>
                Administrator Username
              </label>
              <input
                type="text"
                required
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter admin username"
                className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${ui.bgInput} focus:outline-none focus:border-amber-500`}
              />
            </div>
            <div>
              <label className={`block text-xs font-medium ${ui.textSecondary} mb-1.5`}>
                Password
              </label>
              <input
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${ui.bgInput} focus:outline-none focus:border-amber-500`}
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 disabled:opacity-50 text-slate-950 font-bold text-sm transition shadow-lg shadow-amber-500/20"
            >
              {loading ? 'Signing In...' : 'Sign In to Admin Console'}
            </button>
          </form>
        </div>
      </div>
      <Footer ui={ui} />
    </div>
  );
};
