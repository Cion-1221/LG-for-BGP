// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React from 'react';
import { ThemeTokens } from '../../hooks/useTheme';
import { Footer } from './Footer';

interface NotFoundViewProps {
  ui: ThemeTokens;
  onReturnToLG: () => void;
}

export const NotFoundView: React.FC<NotFoundViewProps> = ({ ui, onReturnToLG }) => (
  <div className={`min-h-screen ${ui.bgPage} flex flex-col`}>
    <div className="flex-1 flex flex-col items-center justify-center p-4">
      <div className={`max-w-md w-full ${ui.bgCard} border rounded-2xl p-8 text-center space-y-4`}>
        <div className="text-3xl font-bold font-mono text-rose-500">404</div>
        <div className={`text-base font-semibold ${ui.textPrimary}`}>Page Not Found</div>
        <p className={`text-xs ${ui.textSecondary} leading-relaxed`}>
          The requested endpoint does not exist on this Looking Glass server.
        </p>
        <button
          onClick={onReturnToLG}
          className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition"
        >
          Return to Looking Glass
        </button>
      </div>
    </div>
    <Footer ui={ui} />
  </div>
);
