'use client';

import clsx from 'clsx';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';

import { useAuth } from '@/components/auth-provider';
import { useTheme } from '@/components/theme-provider';
import { Button } from '@/components/ui/button';
import { getStats } from '@/lib/api';

/**
 * The shared chrome for every signed-in console page: sidebar nav, the
 * mock-mode banner, the dark-mode toggle and sign-out.
 *
 * It also carries the client-side route guard ADR 0014 §1 describes. There
 * is no server-rendered auth gate here because there is no server rendering
 * at request time at all — the shell is a static file. The *real*
 * enforcement is server-side on every `/console/api/*` call
 * (app/console_api.py); this guard only decides what a browser bothers to
 * render, and a user who defeats it sees an empty page and a pile of 401s.
 */

const NAV = [
  { href: '/', label: 'Overview' },
  { href: '/approvals/', label: 'Approvals' },
  { href: '/decisions/', label: 'Decisions' },
] as const;

export function ConsoleShell({ children }: { children: ReactNode }) {
  const { session, ready, signOut } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [mockMode, setMockMode] = useState<boolean | null>(null);

  useEffect(() => {
    if (ready && !session) router.replace('/login');
  }, [ready, session, router]);

  // DEP-004: mock mode must be visible. `/console/api/stats` is the source
  // (it reads `Settings.mock_mode` directly), so this banner can never
  // disagree with /readyz or the X-RealGuard-Mode header.
  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    getStats()
      .then((stats) => {
        if (!cancelled) setMockMode(stats.mock_mode);
      })
      .catch(() => {
        if (!cancelled) setMockMode(null);
      });
    return () => {
      cancelled = true;
    };
  }, [session]);

  if (!ready) {
    return (
      <div className="grid min-h-screen place-items-center text-sm text-muted">
        Loading…
      </div>
    );
  }

  if (!session) {
    return (
      <div className="grid min-h-screen place-items-center text-sm text-muted">
        Redirecting to sign in…
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col">
      {mockMode ? <MockModeBanner /> : null}
      <div className="flex flex-1 flex-col md:flex-row">
        <aside className="shrink-0 border-b border-line bg-surface md:w-60 md:border-b-0 md:border-r">
          <div className="flex items-center gap-2.5 px-5 py-4">
            <ShieldMark />
            <div>
              <p className="text-sm font-semibold leading-tight text-ink">real-guard-v1</p>
              <p className="text-[11px] leading-tight text-muted">reviewer console</p>
            </div>
          </div>
          <nav className="flex gap-1 px-3 pb-3 md:flex-col">
            {NAV.map((item) => {
              const active =
                item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  data-testid={`nav-${item.label.toLowerCase()}`}
                  aria-current={active ? 'page' : undefined}
                  className={clsx(
                    'rounded-lg px-3 py-2 text-sm transition-colors',
                    // A left accent bar as well as colour: hover and active
                    // were otherwise two similar pale backgrounds, which is
                    // ambiguous at a glance (and invisible to anyone who
                    // cannot distinguish the two hues).
                    active
                      ? 'border-l-2 border-brand bg-brand/10 font-semibold text-brand'
                      : 'border-l-2 border-transparent font-medium text-muted hover:bg-elevated hover:text-ink',
                  )}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex flex-wrap items-center justify-end gap-2 border-b border-line bg-surface px-5 py-3">
            <span
              className="mr-auto truncate font-mono text-xs text-muted"
              data-testid="identity-id"
            >
              {session.identity_id}
            </span>
            <ThemeToggle />
            <Button variant="secondary" size="sm" data-testid="logout" onClick={signOut}>
              Sign out
            </Button>
          </header>
          <main className="min-w-0 flex-1 p-5 md:p-7">{children}</main>
        </div>
      </div>
    </div>
  );
}

function MockModeBanner() {
  return (
    <div
      data-testid="mock-mode-banner"
      className="border-b border-warn/30 bg-warn/10 px-5 py-2 text-center text-xs font-medium text-warn"
    >
      MOCK MODE — every completion is synthetic (<code className="font-mono">app/providers/mock.py</code>
      ). No upstream provider is configured.
    </div>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={toggle}
      data-testid="theme-toggle"
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      {theme === 'dark' ? 'Light' : 'Dark'}
    </Button>
  );
}

function ShieldMark() {
  return (
    <span
      aria-hidden="true"
      className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand text-brand-ink"
    >
      <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 3l7 2.6v4.9c0 3.9-2.8 6.6-7 8.3-4.2-1.7-7-4.4-7-8.3V5.6L12 3z" />
        <path d="M9 12l2.3 2.3L15.5 10" />
      </svg>
    </span>
  );
}
