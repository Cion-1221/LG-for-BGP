// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import { useEffect, useMemo, useState } from 'react';
import { ThemeMode } from '../types';

export interface ThemeTokens {
  isDark: boolean;
  bgPage: string;
  bgHeader: string;
  bgCard: string;
  bgSubCard: string;
  bgInput: string;
  borderSubtle: string;
  divideSubtle: string;
  textPrimary: string;
  textSecondary: string;
  textSky: string;
  textEmerald: string;
  textAmber: string;
  textRose: string;
  badgeSky: string;
  badgeEmerald: string;
  badgeAmber: string;
  badgeRose: string;
  layoutContainer: string;
}

export function useTheme() {
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

  const ui = useMemo<ThemeTokens>(
    () => ({
      isDark,
      bgPage: isDark ? 'bg-[#060911] text-slate-100' : 'bg-slate-50 text-slate-900',
      bgHeader: isDark
        ? 'bg-[#0b101d]/95 border-slate-800/80'
        : 'bg-white/95 border-slate-200 shadow-sm',
      bgCard: isDark
        ? 'bg-[#0b101d] border-slate-800/90 shadow-2xl'
        : 'bg-white border-slate-200/90 shadow-sm',
      bgSubCard: isDark ? 'bg-[#060911] border-slate-800' : 'bg-slate-50 border-slate-200',
      bgInput: isDark
        ? 'bg-[#060911] border-slate-800 text-white placeholder:text-slate-500'
        : 'bg-white border-slate-300 text-slate-900 placeholder:text-slate-400',
      borderSubtle: isDark ? 'border-slate-800/70' : 'border-slate-200',
      divideSubtle: isDark ? 'divide-slate-800/50' : 'divide-slate-200',
      textPrimary: isDark ? 'text-white' : 'text-slate-900',
      textSecondary: isDark ? 'text-slate-400' : 'text-slate-600',
      textSky: isDark ? 'text-sky-400' : 'text-sky-700',
      textEmerald: isDark ? 'text-emerald-400' : 'text-emerald-700',
      textAmber: isDark ? 'text-amber-400' : 'text-amber-700',
      textRose: isDark ? 'text-rose-400' : 'text-rose-700',
      badgeSky: isDark
        ? 'bg-sky-500/15 text-sky-400 border-sky-500/30'
        : 'bg-sky-50 text-sky-700 border-sky-200',
      badgeEmerald: isDark
        ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
        : 'bg-emerald-50 text-emerald-700 border-emerald-200',
      badgeAmber: isDark
        ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
        : 'bg-amber-50 text-amber-700 border-amber-200',
      badgeRose: isDark
        ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
        : 'bg-rose-50 text-rose-700 border-rose-200',
      layoutContainer: 'w-full max-w-[96vw] 2xl:max-w-[95vw] mx-auto px-3 sm:px-5',
    }),
    [isDark]
  );

  return { themeMode, setThemeMode, isDark, ui };
}
