'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

/**
 * Dark-mode toggle: a `dark` class on <html>, persisted in `localStorage`,
 * defaulting to the OS preference on a first visit.
 *
 * `localStorage` here rather than the `sessionStorage` the auth mirror uses:
 * a theme choice is a durable user preference with no credential value, and
 * should survive closing the tab. The session mirror should not.
 *
 * The class is *also* set by `app/theme-init.js` — a real, same-origin
 * script file loaded synchronously in <head> — so the correct theme is on
 * <html> before first paint and there is no light-to-dark flash. That has to
 * be an external file rather than the usual inline bootstrap snippet,
 * because app/main.py sends `Content-Security-Policy: default-src 'self'`
 * with no `unsafe-inline` (SEC-008) and a real browser refuses inline
 * scripts outright.
 */

type Theme = 'light' | 'dark';

const STORAGE_KEY = 'rg-console-theme';

interface ThemeContextValue {
  theme: Theme;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark');
}

function initialTheme(): Theme {
  if (typeof window === 'undefined') return 'light';
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
  } catch {
    /* fall through to the OS preference */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  // Static export pre-renders this component on the build machine, where
  // there is no `window` and no user preference — so the first client render
  // must match the server's 'light' output, and the real theme is applied in
  // the effect below (the pre-paint script has already put the right class
  // on <html>, so this reconciliation is invisible).
  const [theme, setTheme] = useState<Theme>('light');

  useEffect(() => {
    const resolved = initialTheme();
    setTheme(resolved);
    applyTheme(resolved);
  }, []);

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      try {
        window.localStorage.setItem(STORAGE_KEY, next);
      } catch {
        /* a refused write only costs persistence, not the toggle itself */
      }
      return next;
    });
  }, []);

  const value = useMemo<ThemeContextValue>(() => ({ theme, toggle }), [theme, toggle]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used inside <ThemeProvider>');
  return context;
}
