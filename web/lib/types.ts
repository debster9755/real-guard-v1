/**
 * Wire shapes returned by `/console/api/*` (app/console_api.py).
 *
 * These mirror that module's JSON exactly. They are hand-written rather than
 * generated: the backend's own source of truth for these values is
 * app/approvals.py's `ApprovalRow`/`ApprovalDecisionRow`, and openapi.json
 * (which CI checks for drift) documents the `/v1/firewall/*` contract, not
 * this UI-only surface. Keeping them here, small and explicit, is honest
 * about that — nothing below claims to be generated from a schema.
 */

/** app/approvals.py's `APPROVAL_STATES` — the complete SPEC.md §9.1 set. */
export const APPROVAL_STATES = [
  'PENDING',
  'APPROVED',
  'RESUMING',
  'DENIED',
  'EXPIRED',
  'CANCELLED',
  'COMPLETED',
  'FAILED',
] as const;

export type ApprovalState = (typeof APPROVAL_STATES)[number];

export interface Session {
  identity_id: string;
  csrf_token: string;
  expires_at: string;
}

export interface Approval {
  approval_id: string;
  transaction_id: string;
  status: ApprovalState;
  risk_level: string;
  reason_codes: string[];
  policy_hits: string[];
  /** APR-012: already-transformed preview content, never the raw request. */
  preview: Record<string, unknown>;
  created_at: string;
  expires_at: string;
}

export interface ApprovalList {
  items: Approval[];
  next_cursor: string | null;
}

export interface Decision {
  approval_id: string;
  decision: 'APPROVE' | 'DENY';
  reviewer_id: string;
  note: string | null;
  from_state: string;
  to_state: string;
  created_at: string;
}

export interface DecisionList {
  items: Decision[];
}

export interface DecideResult {
  approval_id: string;
  decision: string;
  status: ApprovalState;
  outcome: 'applied' | 'replayed';
  decided_at: string;
}

export interface Series {
  name: string;
  value: number;
}

export interface Stats {
  mock_mode: boolean;
  policy_version: string | null;
  approvals_by_state: Record<ApprovalState, number>;
  totals: {
    approvals: number;
    pending: number;
    decisions: number;
    http_requests: number;
  };
  decisions_by_verdict: Series[];
  risk_levels: Series[];
  policy_hits: Series[];
  reason_codes: Series[];
}
