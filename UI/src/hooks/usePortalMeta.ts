// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { useEffect } from 'react';
import { BootstrapResponse } from '../types';

export const MAX_ICON_FILE_BYTES = 256 * 1024; // 256 KB
export const DEFAULT_FAVICON_DATA_URL =
  'data:image/svg+xml;utf8,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0ea5e9"/><stop offset="100%" stop-color="#4f46e5"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#g)"/><text x="32" y="39" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="22" fill="#ffffff">BGP</text></svg>'
  );

export function usePortalMeta(
  boot: BootstrapResponse | null,
  portalMode: 'lg' | 'admin' | 'notfound'
) {
  useEffect(() => {
    const orgTitle = (boot?.settings?.organization_name || '').trim() || 'BGP Looking Glass';
    if (portalMode === 'admin') {
      document.title = `${orgTitle} - Admin`;
    } else if (portalMode === 'notfound') {
      document.title = `404 - ${orgTitle}`;
    } else {
      document.title = orgTitle;
    }
  }, [boot?.settings?.organization_name, portalMode]);

  useEffect(() => {
    const iconHref = (boot?.settings?.favicon_icon || '').trim() || DEFAULT_FAVICON_DATA_URL;
    const ensureLink = (rel: string) => {
      let el = document.querySelector<HTMLLinkElement>(`link[rel="${rel}"]`);
      if (!el) {
        el = document.createElement('link');
        el.rel = rel;
        document.head.appendChild(el);
      }
      el.href = iconHref;
    };
    ensureLink('icon');
    ensureLink('shortcut icon');
  }, [boot?.settings?.favicon_icon]);
}
