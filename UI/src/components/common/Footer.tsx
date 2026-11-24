// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
import React from 'react';
import { ThemeTokens } from '../../hooks/useTheme';

interface FooterProps {
  ui: ThemeTokens;
}

export const Footer: React.FC<FooterProps> = ({ ui }) => (
  <footer className={`border-t ${ui.borderSubtle} py-4 mt-auto`}>
    <div className={`${ui.layoutContainer} flex items-center justify-center text-xs ${ui.textSecondary}`}>
      <span>
        Copyright © {new Date().getFullYear()}{' '}
        <a
          href="mailto:alan.xiao@cionsiu.com"
          className={`font-semibold hover:underline ${ui.textSky}`}
          title="Contact Alan (alan.xiao@cionsiu.com)"
        >
          Alan
        </a>
      </span>
    </div>
  </footer>
);
