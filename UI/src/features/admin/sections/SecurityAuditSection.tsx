// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { api } from '../../../api';
import { ThemeTokens } from '../../../hooks/useTheme';
import { AuditLogEntry, LoginLockEntry } from '../../../types';

interface SecurityAuditSectionProps {
  ui: ThemeTokens;
  auditLogs: AuditLogEntry[];
  loginLocks: LoginLockEntry[];
  setLoginLocks: React.Dispatch<React.SetStateAction<LoginLockEntry[]>>;
  setAdminMsg: (msg: string) => void;
  reloadAdminData: () => Promise<void>;
}

export const SecurityAuditSection: React.FC<SecurityAuditSectionProps> = ({
  ui,
  auditLogs,
  loginLocks,
  setLoginLocks,
  setAdminMsg,
  reloadAdminData,
}) => {
  const [unbanInput, setUnbanInput] = useState('');
  const [auditPage, setAuditPage] = useState<number>(1);
  const [auditPageSize, setAuditPageSize] = useState<number>(20);

  const totalLogs = auditLogs.length;
  const totalPages = Math.max(1, Math.ceil(totalLogs / auditPageSize));
  const currentPage = Math.min(Math.max(1, auditPage), totalPages);
  const startIdx = (currentPage - 1) * auditPageSize;
  const pagedLogs = auditLogs.slice(startIdx, startIdx + auditPageSize);

  return (
    <div className="space-y-6 text-xs">
      <div className={`${ui.bgCard} border rounded-2xl p-6 space-y-4`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className={`text-base font-bold ${ui.textPrimary}`}>
              Login Brute-Force Protection & Manual Unban
            </h2>
            <p className={`text-[11px] ${ui.textSecondary} mt-0.5`}>
              Tracks per-IP and per-(IP + Username) failures (5 attempts / 15m -&gt; 15m lock)
              without globally locking legitimate admins on other IPs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                const targetKey = unbanInput.trim();
                if (!targetKey) return;
                try {
                  const res = await api.unbanLoginLock(targetKey);
                  setLoginLocks(res.locks || []);
                  setUnbanInput('');
                  setAdminMsg(
                    res.removed > 0
                      ? `Unbanned "${targetKey}" (${res.removed} record(s) cleared).`
                      : `No active lock or failure record found for "${targetKey}".`
                  );
                } catch (err: unknown) {
                  setAdminMsg(err instanceof Error ? err.message : 'Unban failed');
                }
              }}
              className="flex items-center gap-1.5"
            >
              <input
                type="text"
                value={unbanInput}
                onChange={(e) => setUnbanInput(e.target.value)}
                placeholder="IP or username (e.g. 1.2.3.4 or admin)"
                className={`px-3 py-1.5 rounded-lg border font-mono w-56 ${ui.bgInput}`}
              />
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition"
              >
                Unban
              </button>
            </form>
            {loginLocks.length > 0 && (
              <button
                type="button"
                onClick={async () => {
                  try {
                    const res = await api.unbanLoginLock('all');
                    setLoginLocks(res.locks || []);
                    setAdminMsg(`Cleared all ${res.removed} login lock/tracking records.`);
                  } catch (err: unknown) {
                    setAdminMsg(err instanceof Error ? err.message : 'Unban all failed');
                  }
                }}
                className={`px-3 py-1.5 rounded-lg border font-semibold transition ${ui.badgeRose}`}
              >
                Unban All
              </button>
            )}
          </div>
        </div>

        {loginLocks.length === 0 ? (
          <div className={`p-4 rounded-xl border text-center ${ui.bgSubCard} ${ui.textSecondary}`}>
            No locked IPs or sessions. Login brute-force protection is active.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono">
              <thead>
                <tr
                  className={`border-b border-slate-200 dark:border-slate-800/70 ${ui.textSecondary}`}
                >
                  <th className="py-2 px-2">Scope</th>
                  <th className="py-2 px-2">Target</th>
                  <th className="py-2 px-2">Failed Attempts</th>
                  <th className="py-2 px-2">Status</th>
                  <th className="py-2 px-2">Last Attempt</th>
                  <th className="py-2 px-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60">
                {loginLocks.map((entry) => (
                  <tr key={entry.key}>
                    <td className="py-2 px-2 uppercase text-sky-700 dark:text-sky-400">
                      {entry.type}
                    </td>
                    <td className={`py-2 px-2 font-bold ${ui.textPrimary}`}>{entry.value}</td>
                    <td className={`py-2 px-2 ${ui.textPrimary}`}>
                      {entry.failures} / {entry.max_failures}
                    </td>
                    <td className="py-2 px-2">
                      <span
                        className={`px-2 py-0.5 rounded border text-[11px] font-semibold ${
                          entry.locked ? ui.badgeRose : ui.badgeAmber
                        }`}
                      >
                        {entry.locked
                          ? `LOCKED (${Math.ceil(entry.remaining_seconds / 60)}m / ${entry.remaining_seconds}s)`
                          : 'Tracking'}
                      </span>
                    </td>
                    <td className={`py-2 px-2 ${ui.textSecondary}`}>
                      {new Date(entry.last_attempt).toLocaleString()}
                    </td>
                    <td className="py-2 px-2 text-right">
                      <button
                        type="button"
                        onClick={async () => {
                          try {
                            const res = await api.unbanLoginLock(entry.key);
                            setLoginLocks(res.locks || []);
                            setAdminMsg(`Manually unbanned ${entry.value}`);
                          } catch (err: unknown) {
                            setAdminMsg(err instanceof Error ? err.message : 'Unban failed');
                          }
                        }}
                        className={`px-2.5 py-1 rounded-lg border font-sans font-semibold transition ${ui.badgeEmerald}`}
                      >
                        Unban
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className={`${ui.bgCard} border rounded-2xl p-6 space-y-4`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className={`text-base font-bold ${ui.textPrimary}`}>
              Query & Administrative Audit Logs
            </h2>
            <p className={`text-[11px] ${ui.textSecondary} mt-0.5`}>
              {totalLogs === 0
                ? 'No audit log entries recorded yet.'
                : `Showing ${startIdx + 1}–${Math.min(startIdx + auditPageSize, totalLogs)} of ${totalLogs} entries`}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center gap-1.5">
              <span className={ui.textSecondary}>Rows per page:</span>
              <select
                value={auditPageSize}
                onChange={(e) => {
                  setAuditPageSize(Number(e.target.value));
                  setAuditPage(1);
                }}
                className={`px-2.5 py-1.5 rounded-lg border font-mono ${ui.bgInput}`}
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <button
              type="button"
              onClick={reloadAdminData}
              className="px-3 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 text-sky-700 dark:text-sky-400 border border-sky-500/30 font-semibold transition"
            >
              Refresh Logs
            </button>

            <button
              type="button"
              onClick={async () => {
                await api.clearCache();
                setAdminMsg('Flushed all cached BGP query results.');
                await reloadAdminData();
              }}
              className="px-3.5 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-700 dark:text-amber-400 border border-amber-500/30 font-semibold transition"
            >
              Flush Route Cache
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono">
            <thead>
              <tr
                className={`border-b border-slate-200 dark:border-slate-800/70 ${ui.textSecondary}`}
              >
                <th className="py-2.5 px-2">Time</th>
                <th className="py-2.5 px-2">User</th>
                <th className="py-2.5 px-2">Client IP</th>
                <th className="py-2.5 px-2">Action</th>
                <th className="py-2.5 px-2">Query Target / Views</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60">
              {pagedLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className={`py-6 text-center font-sans ${ui.textSecondary}`}>
                    No audit log entries available.
                  </td>
                </tr>
              ) : (
                pagedLogs.map((log, i) => (
                  <tr key={startIdx + i}>
                    <td className={`py-2.5 px-2 whitespace-nowrap ${ui.textSecondary}`}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className={`py-2.5 px-2 ${ui.textPrimary}`}>{log.username}</td>
                    <td className="py-2.5 px-2 text-sky-700 dark:text-sky-400">{log.client_ip}</td>
                    <td className="py-2.5 px-2 text-emerald-700 dark:text-emerald-400">
                      {log.action}
                    </td>
                    <td className={`py-2.5 px-2 ${ui.textSecondary}`}>
                      {log.target
                        ? `${log.query_type}: ${log.target} [${log.views}] (${log.duration_ms ?? 0}ms)`
                        : '-'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {totalLogs > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-200 dark:border-slate-800/70">
            <div className={`font-mono ${ui.textSecondary}`}>
              Page <span className={`font-bold ${ui.textPrimary}`}>{currentPage}</span> of{' '}
              <span className={`font-bold ${ui.textPrimary}`}>{totalPages}</span> ({totalLogs} total
              logs)
            </div>

            <div className="flex items-center gap-1.5 font-mono">
              <button
                type="button"
                disabled={currentPage <= 1}
                onClick={() => setAuditPage(1)}
                className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${ui.bgSubCard} ${ui.textPrimary}`}
              >
                « First
              </button>
              <button
                type="button"
                disabled={currentPage <= 1}
                onClick={() => setAuditPage((p) => Math.max(1, p - 1))}
                className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${ui.bgSubCard} ${ui.textPrimary}`}
              >
                ‹ Prev
              </button>
              <button
                type="button"
                disabled={currentPage >= totalPages}
                onClick={() => setAuditPage((p) => Math.min(totalPages, p + 1))}
                className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${ui.bgSubCard} ${ui.textPrimary}`}
              >
                Next ›
              </button>
              <button
                type="button"
                disabled={currentPage >= totalPages}
                onClick={() => setAuditPage(totalPages)}
                className={`px-2.5 py-1 rounded-lg border transition disabled:opacity-40 ${ui.bgSubCard} ${ui.textPrimary}`}
              >
                Last »
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
