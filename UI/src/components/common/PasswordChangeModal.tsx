// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { ThemeTokens } from '../../hooks/useTheme';

interface PasswordChangeModalProps {
  ui: ThemeTokens;
  username: string;
  isMandatory: boolean;
  onClose: () => void;
  onLogout: () => void;
  onSubmitPasswordChange: (currentPassword: string, newPassword: string) => Promise<void>;
}

export const PasswordChangeModal: React.FC<PasswordChangeModalProps> = ({
  ui,
  username,
  isMandatory,
  onClose,
  onLogout,
  onSubmitPasswordChange,
}) => {
  const [curPwd, setCurPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdError, setPwdError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwdError('');
    if (newPwd.trim() === '') {
      setPwdError('New password cannot be empty or whitespace only.');
      return;
    }
    if (newPwd.length < 6) {
      setPwdError('New password must be at least 6 characters long.');
      return;
    }
    if (newPwd !== confirmPwd) {
      setPwdError('New password and confirmation do not match.');
      return;
    }
    try {
      setSubmitting(true);
      // Pass exact password characters without TrimSpace mutation
      await onSubmitPasswordChange(curPwd, newPwd);
      setCurPwd('');
      setNewPwd('');
      setConfirmPwd('');
    } catch (err: unknown) {
      setPwdError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className={`${ui.bgCard} border rounded-2xl max-w-md w-full p-6`}>
        <div className="flex items-center justify-between mb-2">
          <div>
            <h3 className={`font-bold text-base ${ui.textPrimary}`}>
              {isMandatory ? 'Password Change Required' : 'Change Account Password'}
            </h3>
            <p className={`text-xs ${ui.textSecondary}`}>Account: {username}</p>
          </div>
          {!isMandatory && (
            <button
              type="button"
              onClick={onClose}
              className={`${ui.textSecondary} hover:opacity-80 text-sm px-2 py-1`}
            >
              ✕
            </button>
          )}
        </div>

        <p className={`text-xs ${ui.textSecondary} mb-4 leading-relaxed`}>
          {isMandatory
            ? 'For security, you must set a new password before accessing the system.'
            : 'Enter your current password and choose a new password.'}
        </p>

        {pwdError && (
          <div className="mb-4 p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 dark:bg-rose-500/10 dark:border-rose-500/30 dark:text-rose-400 text-xs">
            {pwdError}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Current Password</label>
            <input
              type="password"
              required
              value={curPwd}
              onChange={(e) => setCurPwd(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-lg border ${ui.bgInput} focus:outline-none focus:border-sky-500`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              New Password (minimum 6 characters)
            </label>
            <input
              type="password"
              required
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-lg border ${ui.bgInput} focus:outline-none focus:border-sky-500`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
              Confirm New Password
            </label>
            <input
              type="password"
              required
              value={confirmPwd}
              onChange={(e) => setConfirmPwd(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-lg border ${ui.bgInput} focus:outline-none focus:border-sky-500`}
            />
          </div>
          <div className="flex items-center gap-2 pt-2">
            {isMandatory && (
              <button
                type="button"
                onClick={onLogout}
                className="px-4 py-2.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-white font-medium transition"
              >
                Sign Out
              </button>
            )}
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold transition"
            >
              {submitting ? 'Updating...' : 'Update Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
