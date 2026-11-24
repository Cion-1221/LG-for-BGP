// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React from 'react';
import { api } from '../../../api';
import { DEFAULT_FAVICON_DATA_URL, MAX_ICON_FILE_BYTES } from '../../../hooks/usePortalMeta';
import { ThemeTokens } from '../../../hooks/useTheme';
import { BootstrapResponse, RRNodeConfig, SystemSettings } from '../../../types';

interface GlobalSettingsSectionProps {
  boot: BootstrapResponse;
  setBoot: React.Dispatch<React.SetStateAction<BootstrapResponse | null>>;
  ui: ThemeTokens;
  rrNodeByID: Map<string, RRNodeConfig>;
  setAdminMsg: (msg: string) => void;
  reloadBootstrap: () => Promise<void>;
}

export const GlobalSettingsSection: React.FC<GlobalSettingsSectionProps> = ({
  boot,
  setBoot,
  ui,
  rrNodeByID,
  setAdminMsg,
  reloadBootstrap,
}) => {
  const handleIconFileUpload = (
    field: 'favicon_icon' | 'portal_logo',
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > MAX_ICON_FILE_BYTES) {
      setAdminMsg(
        `Icon file is too large (${Math.ceil(file.size / 1024)} KB). Maximum allowed size is 256 KB.`
      );
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = typeof reader.result === 'string' ? reader.result : '';
      if (!dataUrl.startsWith('data:image/')) {
        setAdminMsg(
          'Unsupported file format. Please upload a PNG, ICO, SVG, WebP, JPG, or GIF image.'
        );
        return;
      }
      setBoot((prev) =>
        prev
          ? {
              ...prev,
              settings: {
                ...prev.settings,
                [field]: dataUrl,
              },
            }
          : prev
      );
      setAdminMsg(
        field === 'favicon_icon'
          ? 'Browser tab favicon loaded for preview. Click "Save Global Settings" to persist.'
          : 'Public Portal header logo loaded for preview. Click "Save Global Settings" to persist.'
      );
    };
    reader.onerror = () => setAdminMsg('Failed to read the selected image file.');
    reader.readAsDataURL(file);
  };

  return (
    <div className={`${ui.bgCard} border rounded-2xl p-6 space-y-6`}>
      <div>
        <h2 className={`text-base font-bold ${ui.textPrimary} mb-1`}>
          Public Portal Access Policy
        </h2>
        <p className={`text-xs ${ui.textSecondary} mb-4`}>
          Control whether visitors opening the Looking Glass (/) can immediately run queries or must
          sign in with an authorized account first.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            onClick={async () => {
              const updated: SystemSettings = { ...boot.settings, access_mode: 'public' };
              await api.updateSettings(updated);
              setAdminMsg('Switched to Public Direct Query Mode (public).');
              await reloadBootstrap();
            }}
            className={`cursor-pointer p-4 rounded-xl border transition ${
              boot.settings.access_mode === 'public'
                ? 'bg-emerald-500/10 border-emerald-500/60'
                : `${ui.bgSubCard} opacity-75 hover:opacity-100`
            }`}
          >
            <div className="font-bold text-sm text-emerald-700 dark:text-emerald-400 mb-1">
              Public Direct Query Mode
            </div>
            <p className={`text-xs ${ui.textSecondary} leading-relaxed`}>
              Visitors opening / immediately query permitted public VRF views without any login
              button or admin link shown.
            </p>
          </div>

          <div
            onClick={async () => {
              const updated: SystemSettings = { ...boot.settings, access_mode: 'auth_required' };
              await api.updateSettings(updated);
              setAdminMsg('Switched to Authenticated Per-Customer Mode (auth_required).');
              await reloadBootstrap();
            }}
            className={`cursor-pointer p-4 rounded-xl border transition ${
              boot.settings.access_mode === 'auth_required'
                ? 'bg-amber-500/10 border-amber-500/60'
                : `${ui.bgSubCard} opacity-75 hover:opacity-100`
            }`}
          >
            <div className="font-bold text-sm text-amber-700 dark:text-amber-400 mb-1">
              Authenticated Account Mode
            </div>
            <p className={`text-xs ${ui.textSecondary} leading-relaxed`}>
              Requires users to sign in before querying, restricting each user to their assigned VRF
              views.
            </p>
          </div>
        </div>
      </div>

      <form
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await api.updateSettings(boot.settings);
            setAdminMsg('Global settings saved.');
            await reloadBootstrap();
          } catch (err: unknown) {
            setAdminMsg(err instanceof Error ? err.message : 'Failed to save global settings');
          }
        }}
        className="space-y-4 pt-5 border-t border-slate-200 dark:border-slate-800/70 text-xs"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
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
              className={`w-full px-3.5 py-2 rounded-lg border ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>Primary ASN</label>
            <input
              type="number"
              value={boot.settings.primary_asn}
              onChange={(e) =>
                setBoot({
                  ...boot,
                  settings: { ...boot.settings, primary_asn: Number(e.target.value) },
                })
              }
              className={`w-full px-3.5 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
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
              className={`w-full px-3.5 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
              Admin URL Path (via config.yaml)
            </label>
            <input
              type="text"
              disabled
              value={`/${boot.settings.admin_secret_slug || 'console'}`}
              className={`w-full px-3.5 py-2 rounded-lg border font-mono opacity-75 ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
              Route Cache TTL (Seconds)
            </label>
            <input
              type="number"
              value={boot.settings.cache_ttl_seconds}
              onChange={(e) =>
                setBoot({
                  ...boot,
                  settings: { ...boot.settings, cache_ttl_seconds: Number(e.target.value) },
                })
              }
              className={`w-full px-3.5 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
              Default Rate Limit (Queries / Min)
            </label>
            <input
              type="number"
              value={boot.settings.rate_limit_per_minute}
              onChange={(e) =>
                setBoot({
                  ...boot,
                  settings: { ...boot.settings, rate_limit_per_minute: Number(e.target.value) },
                })
              }
              className={`w-full px-3.5 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
              AS-Path / Community Max IPv4 Routes{' '}
              <span className={ui.textSky}>(1–5000, default 50)</span>
            </label>
            <input
              type="number"
              min={1}
              max={5000}
              required
              value={boot.settings.max_filter_routes_ipv4 ?? 50}
              onChange={(e) =>
                setBoot({
                  ...boot,
                  settings: {
                    ...boot.settings,
                    max_filter_routes_ipv4: Number(e.target.value),
                  },
                })
              }
              className={`w-full px-3.5 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
          <div>
            <label className={`block font-medium mb-1.5 ${ui.textSecondary}`}>
              AS-Path / Community Max IPv6 Routes{' '}
              <span className={ui.textSky}>(1–5000, default 50)</span>
            </label>
            <input
              type="number"
              min={1}
              max={5000}
              required
              value={boot.settings.max_filter_routes_ipv6 ?? 50}
              onChange={(e) =>
                setBoot({
                  ...boot,
                  settings: {
                    ...boot.settings,
                    max_filter_routes_ipv6: Number(e.target.value),
                  },
                })
              }
              className={`w-full px-3.5 py-2 rounded-lg border font-mono ${ui.bgInput}`}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className={`p-4 rounded-xl border ${ui.bgSubCard} flex items-center gap-4`}>
            <div
              className={`w-12 h-12 rounded-xl border flex items-center justify-center shrink-0 overflow-hidden ${ui.bgCard}`}
              title="Browser Tab Favicon Preview"
            >
              <img
                src={boot.settings.favicon_icon || DEFAULT_FAVICON_DATA_URL}
                alt="Browser Favicon Preview"
                className="w-8 h-8 object-contain"
              />
            </div>
            <div className="min-w-0 flex-1 space-y-1.5">
              <div className={`font-bold ${ui.textPrimary}`}>Browser Tab Favicon</div>
              <p className={`text-[11px] ${ui.textSecondary}`}>
                Replaces the icon next to the browser tab title (PNG / ICO / SVG / WebP, max 256 KB).
              </p>
              <div className="flex flex-wrap items-center gap-2 pt-0.5">
                <label className="cursor-pointer px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold transition inline-flex items-center">
                  <span>Upload Favicon</span>
                  <input
                    type="file"
                    accept=".png,.ico,.svg,.webp,.jpg,.jpeg,.gif,image/*"
                    className="hidden"
                    onChange={(e) => handleIconFileUpload('favicon_icon', e)}
                  />
                </label>
                {boot.settings.favicon_icon && (
                  <button
                    type="button"
                    onClick={() =>
                      setBoot({
                        ...boot,
                        settings: { ...boot.settings, favicon_icon: '' },
                      })
                    }
                    className={`px-2.5 py-1.5 rounded-lg border font-medium transition ${ui.badgeRose}`}
                  >
                    Reset Default
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className={`p-4 rounded-xl border ${ui.bgSubCard} flex items-center gap-4`}>
            {boot.settings.portal_logo ? (
              <div
                className={`w-12 h-12 rounded-xl border flex items-center justify-center shrink-0 overflow-hidden p-1 ${ui.bgCard}`}
                title="Public Portal Header Logo Preview"
              >
                <img
                  src={boot.settings.portal_logo}
                  alt="Public Portal Logo Preview"
                  className="w-10 h-10 object-contain rounded-lg"
                />
              </div>
            ) : (
              <div
                className="w-12 h-12 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center font-bold text-sm text-white shadow-md shadow-sky-500/20 shrink-0"
                title="Default BGP Logo"
              >
                BGP
              </div>
            )}
            <div className="min-w-0 flex-1 space-y-1.5">
              <div className={`font-bold ${ui.textPrimary}`}>Public Portal Header Logo</div>
              <p className={`text-[11px] ${ui.textSecondary}`}>
                Replaces the blue BGP square icon to the left of the Portal Title (PNG / SVG / WebP,
                max 256 KB).
              </p>
              <div className="flex flex-wrap items-center gap-2 pt-0.5">
                <label className="cursor-pointer px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition inline-flex items-center">
                  <span>Upload Portal Logo</span>
                  <input
                    type="file"
                    accept=".png,.ico,.svg,.webp,.jpg,.jpeg,.gif,image/*"
                    className="hidden"
                    onChange={(e) => handleIconFileUpload('portal_logo', e)}
                  />
                </label>
                {boot.settings.portal_logo && (
                  <button
                    type="button"
                    onClick={() =>
                      setBoot({
                        ...boot,
                        settings: { ...boot.settings, portal_logo: '' },
                      })
                    }
                    className={`px-2.5 py-1.5 rounded-lg border font-medium transition ${ui.badgeRose}`}
                  >
                    Reset Default
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        <div>
          <label className={`block font-medium mb-2 ${ui.textSecondary}`}>
            Permitted VRF / Routing Tables in Public Mode:
          </label>
          {boot.all_views.length === 0 ? (
            <div className="text-slate-500 italic">
              No VRF views configured yet. Add a VRF table in Section 3 first.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {boot.all_views.map((v) => {
                const checked = boot.settings.public_allowed_views.includes(v.id);
                return (
                  <label
                    key={v.id}
                    className={`flex items-center gap-2.5 p-3 rounded-xl border cursor-pointer ${ui.bgSubCard}`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => {
                        const cur = boot.settings.public_allowed_views;
                        const next = checked ? cur.filter((x) => x !== v.id) : [...cur, v.id];
                        setBoot({
                          ...boot,
                          settings: { ...boot.settings, public_allowed_views: next },
                        });
                      }}
                    />
                    <span className={`font-semibold ${ui.textPrimary}`}>{v.name}</span>
                    <span className="text-sky-700 dark:text-sky-400 font-mono text-[11px] ml-auto">
                      {v.vrf_name} (
                      {v.rr_node_ids && v.rr_node_ids.length > 0
                        ? v.rr_node_ids.includes('all')
                          ? 'ALL RRs'
                          : v.rr_node_ids.map((id) => rrNodeByID.get(id)?.name || id).join(', ')
                        : v.pop && v.pop !== 'all'
                          ? v.pop
                          : 'ALL'}
                      )
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
  );
};
