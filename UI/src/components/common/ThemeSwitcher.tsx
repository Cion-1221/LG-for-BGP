// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React from 'react';
import { ThemeMode } from '../../types';

interface ThemeSwitcherProps {
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  isDark: boolean;
}

export const ThemeSwitcher: React.FC<ThemeSwitcherProps> = ({
  themeMode,
  setThemeMode,
  isDark,
}) => (
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
