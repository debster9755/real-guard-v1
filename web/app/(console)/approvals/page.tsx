'use client';

import { useCallback, useEffect, useState } from 'react';

import { useAuth } from '@/components/auth-provider';
import { Badge, riskTone, stateTone } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Modal } from '@/components/ui/modal';
import { EmptyRow, Table, Td, Th } from '@/components/ui/table';
import { Tabs } from '@/components/ui/tabs';
import { decide, getApprovals } from '@/lib/api';
import { compactUtc, timeAgo, timeUntil } from '@/lib/format';
import { APPROVAL_STATES, type Approval } from '@/lib/types';

/**
 * The approval queue. Tabs are exactly `app/approvals.APPROVAL_STATES` —
 * the same vocabulary `list_approvals(statuses=…)` accepts and
 * `/console/api/approvals` validates against, imported from one place
 * (lib/types.ts) rather than re-typed here.
 *
 * Deciding calls `POST /console/api/approvals/{id}/decide`, which calls the
 * same `app/approvals.decide_and_resume()` the HTMX dashboard and the
 * canonical JSON endpoint call. On success the queue is refetched rather
 * than optimistically patched: an APPROVE resumes the held request inline
 * (APR-011), so the row's real final state is `COMPLETED`, `DENIED` or
 * `FAILED` depending on what the resume and the output guard did — a value
 * this client cannot predict and must not guess.
 */
export default function ApprovalsPage() {
  const { session } = useAuth();
  const [status, setStatus] = useState<string>('PENDING');
  const [rows, setRows] = useState<Approval[] | null>(null);
  const [selected, setSelected] = useState<Approval | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  const load = useCallback(
    (nextStatus: string) => {
      setRows(null);
      getApprovals(nextStatus)
        .then((list) => setRows(list.items))
        .catch((caught: Error) => {
          setRows([]);
          setError(caught.message);
        });
    },
    [],
  );

  useEffect(() => load(status), [status, load]);

  function openReview(approval: Approval) {
    setSelected(approval);
    setNote('');
    setError(null);
  }

  async function submitDecision(decision: 'APPROVE' | 'DENY') {
    if (!selected || !session) return;
    // Enforced client-side for a usable UI *and* server-side by
    // app/approvals.decide_approval() (422 INVALID_REQUEST) — the button
    // being disabled is a convenience, never the guarantee.
    if (decision === 'DENY' && note.trim().length === 0) {
      setError('A non-empty note is required when denying an approval.');
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const result = await decide(
        selected.approval_id,
        decision,
        note.trim() === '' ? null : note.trim(),
        session.csrf_token,
      );
      setSelected(null);
      setFlash(
        `${result.decision} recorded — ${result.approval_id} is now ${result.status}` +
          (result.outcome === 'replayed' ? ' (replayed, idempotent)' : ''),
      );
      load(status);
    } catch (caught) {
      // A real failure — an already-decided or expired approval, a stale
      // CSRF token — is shown, never swallowed.
      setError(caught instanceof Error ? caught.message : 'The decision failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5" data-testid="approvals-page">
      <div>
        <h1 className="text-lg font-semibold text-ink">Approval queue</h1>
        <p className="mt-1 text-sm text-muted">
          Requests held for human review. Previews are the transformed content only
          (APR-012) — never the raw request.
        </p>
      </div>

      <Tabs tabs={APPROVAL_STATES} active={status} onChange={setStatus} />

      {flash ? (
        <p
          data-testid="decision-flash"
          className="rounded-lg border border-ok/30 bg-ok/10 px-4 py-2.5 text-sm text-ok"
        >
          {flash}
        </p>
      ) : null}

      {error && !selected ? (
        <p
          role="alert"
          data-testid="queue-error"
          className="rounded-lg border border-danger/30 bg-danger/10 px-4 py-2.5 text-sm text-danger"
        >
          {error}
        </p>
      ) : null}

      <Card>
        <Table>
          <thead>
            <tr>
              <Th>Approval</Th>
              <Th>State</Th>
              <Th>Risk</Th>
              <Th>Reason codes</Th>
              <Th>Created</Th>
              <Th>Expires</Th>
              <Th className="text-right">Review</Th>
            </tr>
          </thead>
          <tbody>
            {rows === null ? (
              <EmptyRow colSpan={7}>Loading…</EmptyRow>
            ) : rows.length === 0 ? (
              <EmptyRow colSpan={7}>No approvals in {status}.</EmptyRow>
            ) : (
              rows.map((row) => (
                <tr key={row.approval_id} data-testid={`row-${row.approval_id}`}>
                  <Td>
                    <span className="font-mono text-xs">{row.approval_id}</span>
                  </Td>
                  <Td>
                    <Badge tone={stateTone(row.status)}>{row.status}</Badge>
                  </Td>
                  <Td>
                    <Badge tone={riskTone(row.risk_level)}>{row.risk_level}</Badge>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {row.reason_codes.length === 0 ? (
                        <span className="text-xs text-muted">—</span>
                      ) : (
                        row.reason_codes.map((code) => <Badge key={code}>{code}</Badge>)
                      )}
                    </div>
                  </Td>
                  <Td>
                    <span
                      className="whitespace-nowrap text-xs text-muted"
                      title={row.created_at}
                    >
                      {timeAgo(row.created_at)}
                    </span>
                  </Td>
                  <Td>
                    <span
                      className="whitespace-nowrap text-xs text-muted"
                      title={row.expires_at}
                    >
                      {timeUntil(row.expires_at)}
                    </span>
                  </Td>
                  <Td className="text-right">
                    <Button
                      size="sm"
                      variant="secondary"
                      data-testid={`review-${row.approval_id}`}
                      onClick={() => openReview(row)}
                    >
                      Review
                    </Button>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
      </Card>

      <Modal
        open={selected !== null}
        title={selected ? `Review ${selected.approval_id}` : 'Review'}
        onClose={() => setSelected(null)}
        footer={
          selected && selected.status === 'PENDING' ? (
            <>
              <Button
                variant="deny"
                size="sm"
                data-testid="deny-button"
                disabled={busy || note.trim().length === 0}
                title={
                  note.trim().length === 0 ? 'A note is required when denying' : undefined
                }
                onClick={() => submitDecision('DENY')}
              >
                Deny
              </Button>
              <Button
                variant="approve"
                size="sm"
                data-testid="approve-button"
                disabled={busy}
                onClick={() => submitDecision('APPROVE')}
              >
                {busy ? 'Working…' : 'Approve'}
              </Button>
            </>
          ) : (
            <span className="text-xs text-muted">
              This approval is no longer PENDING and cannot be decided.
            </span>
          )
        }
      >
        {selected ? (
          <div className="space-y-4">
            <dl className="grid gap-3 sm:grid-cols-2">
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Transaction
                </dt>
                <dd className="mt-0.5 break-all font-mono text-xs text-ink">
                  {selected.transaction_id}
                </dd>
              </div>
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Risk level
                </dt>
                <dd className="mt-0.5">
                  <Badge tone={riskTone(selected.risk_level)}>{selected.risk_level}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Reason codes
                </dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {selected.reason_codes.length === 0 ? (
                    <span className="text-xs text-muted">—</span>
                  ) : (
                    selected.reason_codes.map((code) => (
                      <Badge key={code} tone="warn">
                        {code}
                      </Badge>
                    ))
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Created
                </dt>
                <dd className="mt-0.5 font-mono text-xs text-ink">
                  {compactUtc(selected.created_at)}
                </dd>
              </div>
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Expires (APR-007)
                </dt>
                <dd className="mt-0.5 font-mono text-xs text-ink">
                  {compactUtc(selected.expires_at)}{' '}
                  <span className="text-muted">({timeUntil(selected.expires_at)})</span>
                </dd>
              </div>
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Policy hits
                </dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {selected.policy_hits.length === 0 ? (
                    <span className="text-xs text-muted">—</span>
                  ) : (
                    selected.policy_hits.map((hit) => (
                      <Badge key={hit} tone="brand">
                        {hit}
                      </Badge>
                    ))
                  )}
                </dd>
              </div>
            </dl>

            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                Transformed preview (APR-012)
              </p>
              <pre
                data-testid="preview-json"
                className="mt-1.5 max-h-72 overflow-auto rounded-lg border border-line bg-canvas p-3 font-mono text-xs leading-relaxed text-ink"
              >
                {JSON.stringify(selected.preview, null, 2)}
              </pre>
            </div>

            <div>
              <label
                htmlFor="decision-note"
                className="text-[11px] font-semibold uppercase tracking-wider text-muted"
              >
                Note <span className="normal-case">(required to deny)</span>
              </label>
              <textarea
                id="decision-note"
                rows={2}
                value={note}
                onChange={(event) => setNote(event.target.value)}
                data-testid="decision-note"
                className="mt-1.5 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink"
                placeholder="Why this decision was made"
              />
            </div>

            {error ? (
              <p
                role="alert"
                data-testid="decision-error"
                className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger"
              >
                {error}
              </p>
            ) : null}
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
