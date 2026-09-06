'use client';

import { useEffect, useState } from 'react';

import { Badge, stateTone } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { EmptyRow, Table, Td, Th } from '@/components/ui/table';
import { getDecisions } from '@/lib/api';
import { compactUtc } from '@/lib/format';
import type { Decision } from '@/lib/types';

/**
 * Decision history — `GET /console/api/decisions`, which is
 * `app/approvals.list_recent_decisions()`: the same append-only
 * `ApprovalDecisionRow`s (DAT-004) the HTMX dashboard's history panel
 * renders, not a parallel query path.
 *
 * A `reviewer_id` of `system` is a machine decision the resume worker
 * recorded — an ARGUMENTS_CHANGED mismatch (APR-013) or an output-guard DENY
 * (SYS-014) — not a human one, and is labelled as such rather than shown as
 * an anonymous reviewer.
 */
export default function DecisionsPage() {
  const [rows, setRows] = useState<Decision[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDecisions()
      .then((list) => setRows(list.items))
      .catch((caught: Error) => {
        setRows([]);
        setError(caught.message);
      });
  }, []);

  return (
    <div className="space-y-5" data-testid="decisions-page">
      <div>
        <h1 className="text-lg font-semibold text-ink">Decision history</h1>
        <p className="mt-1 text-sm text-muted">
          The most recent recorded approval decisions, newest first.
        </p>
      </div>

      {error ? (
        <p
          role="alert"
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
              <Th>Decision</Th>
              <Th>Transition</Th>
              <Th>Reviewer</Th>
              <Th>Note</Th>
              <Th>Recorded</Th>
            </tr>
          </thead>
          <tbody>
            {rows === null ? (
              <EmptyRow colSpan={6}>Loading…</EmptyRow>
            ) : rows.length === 0 ? (
              <EmptyRow colSpan={6}>No decisions recorded yet.</EmptyRow>
            ) : (
              rows.map((row) => (
                <tr key={`${row.approval_id}-${row.created_at}-${row.decision}`}>
                  <Td>
                    <span className="font-mono text-xs">{row.approval_id}</span>
                  </Td>
                  <Td>
                    <Badge tone={row.decision === 'APPROVE' ? 'ok' : 'danger'}>
                      {row.decision}
                    </Badge>
                  </Td>
                  <Td>
                    <span className="flex items-center gap-1.5 whitespace-nowrap">
                      <Badge tone={stateTone(row.from_state)}>{row.from_state}</Badge>
                      <span className="text-muted">&rarr;</span>
                      <Badge tone={stateTone(row.to_state)}>{row.to_state}</Badge>
                    </span>
                  </Td>
                  <Td>
                    {row.reviewer_id === 'system' ? (
                      <Badge tone="info">system</Badge>
                    ) : (
                      <span className="font-mono text-xs">{row.reviewer_id}</span>
                    )}
                  </Td>
                  <Td>
                    <span className="text-xs text-muted">{row.note ?? '—'}</span>
                  </Td>
                  <Td>
                    <span
                      className="whitespace-nowrap text-xs text-muted"
                      title={row.created_at}
                    >
                      {compactUtc(row.created_at)}
                    </span>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
      </Card>
    </div>
  );
}
