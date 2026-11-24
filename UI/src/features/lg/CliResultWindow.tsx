// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React, { useState } from 'react';
import { ThemeTokens } from '../../hooks/useTheme';
import { ViewQueryResult } from '../../types';

interface CliResultWindowProps {
  ui: ThemeTokens;
  viewRes: ViewQueryResult;
}

export const CliResultWindow: React.FC<CliResultWindowProps> = ({ ui, viewRes }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard?.writeText(viewRes.raw_output);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div
      className={`cli-terminal border rounded-2xl overflow-hidden shadow-xl ${
        ui.isDark ? 'bg-[#070a12] border-slate-800/90' : 'bg-slate-900 border-slate-300'
      }`}
    >
      <div
        className={`px-5 py-3 border-b flex flex-wrap items-center justify-between gap-3 ${
          ui.isDark ? 'bg-[#0c1220] border-slate-800/90' : 'bg-slate-800 border-slate-700'
        }`}
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 mr-1">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <span className="font-bold text-sm text-white">{viewRes.view.name}</span>
          <span className="text-[11px] px-2 py-0.5 rounded-md bg-sky-500/20 text-sky-300 border border-sky-500/30 font-mono">
            {viewRes.view.vrf_name}
          </span>
          <span className="text-[11px] px-2 py-0.5 rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
            Matched: {viewRes.matched_prefix}
          </span>
          <span className="text-xs text-slate-300 font-mono">
            {viewRes.total_paths} {viewRes.total_paths === 1 ? 'Path' : 'Paths'} ·{' '}
            {viewRes.query_time_ms}ms
          </span>
          {viewRes.cached && (
            <span className="text-[10px] px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono uppercase">
              Cached
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="px-3 py-1 rounded-lg bg-slate-950/80 hover:bg-slate-950 text-xs font-mono text-slate-200 border border-slate-700 transition"
        >
          {copied ? '✓ Copied' : 'Copy Output'}
        </button>
      </div>

      <pre className="cli-terminal p-5 text-xs font-mono text-emerald-300 bg-[#050811] whitespace-pre-wrap break-words leading-6 selection:bg-sky-500/40 selection:text-white">
        {viewRes.raw_output}
      </pre>
    </div>
  );
};
