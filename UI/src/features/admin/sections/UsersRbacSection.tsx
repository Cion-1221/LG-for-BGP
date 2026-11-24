// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { api } from '../../../api';
import { ThemeTokens } from '../../../hooks/useTheme';
import { BootstrapResponse, RouteViewMeta, UserAccount, UserFormState } from '../../../types';

interface UsersRbacSectionProps {
  boot: BootstrapResponse;
  ui: ThemeTokens;
  users: UserAccount[];
  viewByID: Map<string, RouteViewMeta>;
  setAdminMsg: (msg: string) => void;
  reloadAll: () => Promise<void>;
}

const createBlankUserForm = (allViews: RouteViewMeta[]): UserFormState => ({
  username: '',
  password: '',
  display_name: '',
  company: '',
  customer_asn: 0,
  role: 'customer',
  allowed_views: allViews.map((v) => v.id),
  rate_limit_per_minute: 60,
  enabled: true,
  must_change_password: true,
  notes: '',
});

export const UsersRbacSection: React.FC<UsersRbacSectionProps> = ({
  boot,
  ui,
  users,
  viewByID,
  setAdminMsg,
  reloadAll,
}) => {
  const [editingUser, setEditingUser] = useState<UserFormState>(() =>
    createBlankUserForm(boot.all_views)
  );

  const isDefaultSuperAdmin =
    !!editingUser.id && editingUser.username.trim().toLowerCase() === 'admin';

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 text-xs">
      <div className={`lg:col-span-5 ${ui.bgCard} border rounded-2xl p-6`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className={`text-sm font-bold ${ui.textPrimary}`}>
            {editingUser.id ? `Edit Account: ${editingUser.username}` : 'Create Account'}
          </h3>
          {editingUser.id && (
            <button
              type="button"
              onClick={() => setEditingUser(createBlankUserForm(boot.all_views))}
              className="text-sky-700 dark:text-sky-400 hover:underline text-[11px] font-medium"
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
              setEditingUser(createBlankUserForm(boot.all_views));
              await reloadAll();
            } catch (err: unknown) {
              setAdminMsg(err instanceof Error ? err.message : 'Save failed');
            }
          }}
          className="space-y-3.5"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Username *</label>
              <input
                type="text"
                required
                disabled={isDefaultSuperAdmin}
                value={editingUser.username}
                onChange={(e) => setEditingUser({ ...editingUser, username: e.target.value })}
                className={`w-full px-3 py-2 rounded-lg border font-mono disabled:opacity-70 ${ui.bgInput}`}
              />
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                Password {editingUser.id ? '(Blank = keep)' : '*'}
              </label>
              <input
                type="password"
                required={!editingUser.id}
                value={editingUser.password}
                onChange={(e) => setEditingUser({ ...editingUser, password: e.target.value })}
                className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Display Name</label>
              <input
                type="text"
                value={editingUser.display_name}
                onChange={(e) =>
                  setEditingUser({
                    ...editingUser,
                    display_name: e.target.value,
                    company: editingUser.company || e.target.value,
                  })
                }
                placeholder="e.g. NOC Engineer / Tenant A"
                className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
              />
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                Company / Organization
              </label>
              <input
                type="text"
                value={editingUser.company}
                onChange={(e) => setEditingUser({ ...editingUser, company: e.target.value })}
                placeholder="e.g. Example Telecom Ltd."
                className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Role</label>
              <select
                disabled={isDefaultSuperAdmin}
                value={editingUser.role}
                onChange={(e) =>
                  setEditingUser({
                    ...editingUser,
                    role: e.target.value as 'admin' | 'noc' | 'customer',
                  })
                }
                className={`w-full px-3 py-2 rounded-lg border disabled:opacity-70 ${ui.bgInput}`}
              >
                <option value="customer">Customer</option>
                <option value="noc">NOC Engineer</option>
                <option value="admin">Administrator</option>
              </select>
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Customer ASN</label>
              <input
                type="number"
                min={0}
                value={editingUser.customer_asn}
                onChange={(e) =>
                  setEditingUser({ ...editingUser, customer_asn: Number(e.target.value) || 0 })
                }
                placeholder="e.g. 65001"
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              />
            </div>
            <div>
              <label className={`block font-medium mb-1 ${ui.textSecondary}`}>
                Rate Limit (/min)
              </label>
              <input
                type="number"
                min={1}
                max={10000}
                required
                value={editingUser.rate_limit_per_minute}
                onChange={(e) =>
                  setEditingUser({
                    ...editingUser,
                    rate_limit_per_minute: Number(e.target.value) || 60,
                  })
                }
                className={`w-full px-3 py-2 rounded-lg border font-mono ${ui.bgInput}`}
              />
            </div>
          </div>

          <div>
            <label className={`block font-medium mb-1 ${ui.textSecondary}`}>Notes / Remarks</label>
            <input
              type="text"
              value={editingUser.notes}
              onChange={(e) => setEditingUser({ ...editingUser, notes: e.target.value })}
              placeholder="Optional circuit ID, contract reference, or remarks"
              className={`w-full px-3 py-2 rounded-lg border ${ui.bgInput}`}
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
            <label
              className={`flex items-center gap-2.5 p-2.5 rounded-lg border cursor-pointer font-medium ${
                editingUser.enabled ? ui.badgeEmerald : ui.badgeRose
              }`}
            >
              <input
                type="checkbox"
                disabled={isDefaultSuperAdmin}
                checked={editingUser.enabled}
                onChange={(e) => setEditingUser({ ...editingUser, enabled: e.target.checked })}
              />
              <span>{editingUser.enabled ? 'Account Enabled' : 'Account Disabled'}</span>
            </label>

            <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-400 cursor-pointer font-medium">
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
              <span>Force pwd change on login</span>
            </label>
          </div>

          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
              Authorized BGP VRF Views:
            </label>
            {boot.all_views.length === 0 ? (
              <div className="text-slate-500 italic">No VRF views configured.</div>
            ) : (
              <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
                {boot.all_views.map((v) => {
                  const checked =
                    editingUser.role === 'admin' || editingUser.allowed_views.includes(v.id);
                  return (
                    <label
                      key={v.id}
                      className={`flex items-center gap-2 p-2.5 rounded-lg border cursor-pointer ${ui.bgSubCard}`}
                    >
                      <input
                        type="checkbox"
                        disabled={editingUser.role === 'admin'}
                        checked={checked}
                        onChange={() => {
                          const cur = editingUser.allowed_views;
                          const next = checked ? cur.filter((x) => x !== v.id) : [...cur, v.id];
                          setEditingUser({ ...editingUser, allowed_views: next });
                        }}
                      />
                      <span className={`font-semibold ${ui.textPrimary}`}>{v.name}</span>
                      <span className="text-sky-700 dark:text-sky-400 font-mono text-[11px] ml-auto">
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

      <div className={`lg:col-span-7 ${ui.bgCard} border rounded-2xl p-6 overflow-x-auto`}>
        <h3 className={`text-sm font-bold ${ui.textPrimary} mb-4`}>
          Configured Accounts ({users.length})
        </h3>
        <table className="w-full text-left">
          <thead>
            <tr className={`border-b border-slate-200 dark:border-slate-800/70 ${ui.textSecondary}`}>
              <th className="py-2.5 px-2">Account / Organization</th>
              <th className="py-2.5 px-2">Role & Status</th>
              <th className="py-2.5 px-2">Quota</th>
              <th className="py-2.5 px-2">Authorized VRF Views</th>
              <th className="py-2.5 px-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60">
            {users.map((u) => {
              const activeViews =
                u.role === 'admin'
                  ? boot.all_views
                  : (u.allowed_views || [])
                      .map((vid) => viewByID.get(vid))
                      .filter((v): v is RouteViewMeta => !!v);
              return (
                <tr key={u.id} className={u.enabled ? '' : 'opacity-60'}>
                  <td className="py-3 px-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={`font-bold ${ui.textPrimary}`}>{u.username}</span>
                      {u.customer_asn ? (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${ui.badgeSky}`}>
                          AS{u.customer_asn}
                        </span>
                      ) : null}
                      {u.must_change_password && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30 font-mono">
                          Pwd Reset Req
                        </span>
                      )}
                    </div>
                    <div className={ui.textSecondary}>
                      {u.display_name}
                      {u.company && u.company !== u.display_name ? ` · ${u.company}` : ''}
                    </div>
                    {u.notes && (
                      <div className={`text-[11px] italic ${ui.textSecondary}`}>{u.notes}</div>
                    )}
                  </td>
                  <td className="py-3 px-2 space-y-1">
                    <div className="font-mono uppercase text-sky-700 dark:text-sky-400 font-semibold">
                      {u.role}
                    </div>
                    <span
                      className={`inline-block text-[10px] px-1.5 py-0.5 rounded border font-mono font-semibold ${
                        u.enabled ? ui.badgeEmerald : ui.badgeRose
                      }`}
                    >
                      {u.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                  <td className={`py-3 px-2 font-mono ${ui.textSecondary}`}>
                    {u.rate_limit_per_minute}/min
                  </td>
                  <td className="py-3 px-2">
                    {activeViews.length === 0 ? (
                      <span className="text-slate-500 italic">None</span>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {activeViews.map((v) => (
                          <span
                            key={v.id}
                            className="px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30 font-mono text-[11px]"
                            title={`ID: ${v.id}`}
                          >
                            {v.vrf_name} ({v.name})
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-2 space-x-2 whitespace-nowrap">
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
                          rate_limit_per_minute: u.rate_limit_per_minute || 60,
                          enabled: u.enabled,
                          must_change_password: !!u.must_change_password,
                          notes: u.notes || '',
                        })
                      }
                      className="text-sky-700 dark:text-sky-400 hover:underline font-medium"
                    >
                      Edit
                    </button>
                    {u.username.toLowerCase() !== 'admin' && (
                      <>
                        <button
                          onClick={async () => {
                            try {
                              await api.saveUser({ ...u, enabled: !u.enabled });
                              setAdminMsg(
                                `Account ${u.username} is now ${!u.enabled ? 'ENABLED' : 'DISABLED'}`
                              );
                              await reloadAll();
                            } catch (err: unknown) {
                              setAdminMsg(err instanceof Error ? err.message : 'Update failed');
                            }
                          }}
                          className="text-amber-600 dark:text-amber-400 hover:underline font-medium"
                        >
                          {u.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          onClick={async () => {
                            try {
                              await api.deleteUser(u.id);
                              setAdminMsg(`Deleted account ${u.username}`);
                              await reloadAll();
                            } catch (err: unknown) {
                              setAdminMsg(err instanceof Error ? err.message : 'Delete failed');
                            }
                          }}
                          className="text-rose-500 hover:underline font-medium"
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
