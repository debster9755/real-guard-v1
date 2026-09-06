'use client';

import { useRouter } from 'next/navigation';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import * as api from '@/lib/api';
import type { Session } from '@/lib/types';

/**
 * Client-side auth state for the console. ADR 0014 §1.
 *
 * The session itself lives in the `HttpOnly` `rg_console_session` cookie,
 * which JavaScript cannot read — this context holds only what the login /
 * session-restore *response body* returned: the identity id, the CSRF token
 * and the expiry, mirrored into `sessionStorage`.
 *
 * `sessionStorage`, not `localStorage`, deliberately: the cookie is a
 * browser-session-scoped credential, so the client-side mirror of it should
 * die with the tab rather than outlive it in a way the cookie does not.
 */

const STORAGE_KEY = 'rg-console-session';

interface AuthContextValue {
  session: Session | null;
  /** `null` while the initial `GET /console/api/session` probe is in flight. */
  ready: boolean;
  signIn: (reviewerKey: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readStoredSession(): Session | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

function writeStoredSession(session: Session | null): void {
  if (typeof window === 'undefined') return;
  try {
    if (session) window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* private-mode storage refusal must not break sign-in */
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);

  // Any 401 from any call, anywhere, lands here: drop client state and go
  // back to the sign-in screen. Registered once, globally.
  useEffect(() => {
    api.setUnauthorizedHandler(() => {
      setSession(null);
      writeStoredSession(null);
      router.replace('/login');
    });
    return () => api.setUnauthorizedHandler(null);
  }, [router]);

  // Session restore on first mount: the cookie may still be valid from a
  // previous page load even when sessionStorage was cleared, and vice versa
  // — the server's answer is the one that counts, so we always ask it.
  useEffect(() => {
    let cancelled = false;
    const stored = readStoredSession();
    if (stored) setSession(stored);

    api
      .getSession()
      .then((fresh) => {
        if (cancelled) return;
        setSession(fresh);
        writeStoredSession(fresh);
      })
      .catch(() => {
        if (cancelled) return;
        setSession(null);
        writeStoredSession(null);
      })
      .finally(() => {
        if (!cancelled) setReady(true);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const signIn = useCallback(
    async (reviewerKey: string) => {
      const fresh = await api.login(reviewerKey);
      setSession(fresh);
      writeStoredSession(fresh);
      router.replace('/');
    },
    [router],
  );

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* clearing local state matters more than the server round-trip */
    }
    setSession(null);
    writeStoredSession(null);
    router.replace('/login');
  }, [router]);

  const value = useMemo<AuthContextValue>(
    () => ({ session, ready, signIn, signOut }),
    [session, ready, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>');
  return context;
}
