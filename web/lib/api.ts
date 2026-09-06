import type {
  ApprovalList,
  DecideResult,
  DecisionList,
  Session,
  Stats,
} from './types';

/**
 * The single `fetch` wrapper every page uses. ADR 0014 §1.
 *
 * - `credentials: 'include'` on *every* request, so the `rg_console_session`
 *   cookie (HttpOnly, `Path=/console/api`) is attached. Same-origin, so this
 *   needs no CORS configuration anywhere.
 * - `X-CSRF-Token` on mutating requests only (SEC-007). The token comes from
 *   the auth context, which got it from the login/session response body.
 * - A 401 from any call clears client auth state and sends the user to
 *   `/console/login`. That redirect is a convenience, not the security
 *   boundary: the real enforcement is server-side on every `/console/api/*`
 *   route (app/console_api.py), which is what actually refuses the data.
 */

export const API_BASE = '/console/api';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

type UnauthorizedHandler = () => void;

let unauthorizedHandler: UnauthorizedHandler | null = null;

/** Registered once by the auth provider; invoked on any 401. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
  csrfToken?: string;
  idempotencyKey?: string;
  /** Login and the session probe must not trigger the global 401 redirect:
   *  one is *how* you authenticate, the other is the guard's own probe. */
  suppressUnauthorizedHandler?: boolean;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, csrfToken, idempotencyKey } = options;

  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    credentials: 'include',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && !options.suppressUnauthorizedHandler) {
    unauthorizedHandler?.();
  }

  if (!response.ok) {
    // app/console_api.py's flat shape: {"error": message, "code": ErrorCode}.
    // Anything that is not that shape (a proxy's own error page, say) still
    // has to surface something honest rather than "undefined".
    let message = `Request failed with status ${response.status}.`;
    let code = 'UNKNOWN';
    try {
      const payload = (await response.json()) as { error?: string; code?: string };
      if (typeof payload.error === 'string') message = payload.error;
      if (typeof payload.code === 'string') code = payload.code;
    } catch {
      /* non-JSON body; keep the status-derived message above */
    }
    throw new ApiError(response.status, code, message);
  }

  return (await response.json()) as T;
}

export function login(reviewerKey: string): Promise<Session> {
  return request<Session>('/login', {
    method: 'POST',
    body: { reviewer_key: reviewerKey },
    suppressUnauthorizedHandler: true,
  });
}

export function logout(): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/logout', { method: 'POST' });
}

export function getSession(): Promise<Session> {
  return request<Session>('/session', { suppressUnauthorizedHandler: true });
}

export function getApprovals(status?: string): Promise<ApprovalList> {
  const query = status ? `?status=${encodeURIComponent(status)}` : '';
  return request<ApprovalList>(`/approvals${query}`);
}

export function getDecisions(): Promise<DecisionList> {
  return request<DecisionList>('/decisions');
}

export function getStats(): Promise<Stats> {
  return request<Stats>('/stats');
}

export function decide(
  approvalId: string,
  decision: 'APPROVE' | 'DENY',
  note: string | null,
  csrfToken: string,
): Promise<DecideResult> {
  return request<DecideResult>(`/approvals/${encodeURIComponent(approvalId)}/decide`, {
    method: 'POST',
    body: { decision, note },
    csrfToken,
    // API-007: a fresh key per click, so a double-click replays (APR-010)
    // rather than racing two distinct decisions against one approval.
    idempotencyKey: newIdempotencyKey(),
  });
}

function newIdempotencyKey(): string {
  // `crypto.randomUUID` needs a secure context; a plain-HTTP LAN deployment
  // of this MVP is a supported configuration, so fall back rather than throw.
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `idm-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
