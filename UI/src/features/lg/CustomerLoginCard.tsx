// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { ThemeTokens } from '../../hooks/useTheme';

interface CustomerLoginCardProps {
  ui: ThemeTokens;
  organizationName: string;
  onLogin: (username: string, password: string) => Promise<void>;
}

export const CustomerLoginCard: React.FC<CustomerLoginCardProps> = ({
  ui,
  organizationName,
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
    <div className={`max-w-md mx-auto mt-12 ${ui.bgCard} border rounded-2xl p-7`}>
      <h2 className={`text-base font-bold ${ui.textPrimary} mb-1`}>
        Sign In Required — {organizationName}
      </h2>
      <p className={`text-xs ${ui.textSecondary} mb-5`}>
        Please sign in with your authorized account to query BGP routing tables.
      </p>
      {error && (
        <div className={`mb-4 p-3 rounded-lg border text-xs ${ui.badgeRose}`}>{error}</div>
      )}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className={`block text-xs font-medium ${ui.textSecondary} mb-1.5`}>
            Username
          </label>
          <input
            type="text"
            required
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${ui.bgInput} focus:outline-none focus:border-sky-500`}
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
            className={`w-full px-3.5 py-2.5 rounded-lg border text-sm ${ui.bgInput} focus:outline-none focus:border-sky-500`}
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold text-sm transition shadow-lg shadow-sky-600/20"
        >
          {loading ? 'Signing In...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
};
