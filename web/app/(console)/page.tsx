'use client';

import { useCallback, useEffect, useState } from 'react';

import { PolicyHitsChart, VerdictChart } from '@/components/charts';
import { Badge, stateTone } from '@/components/ui/badge';
import { Card, CardBody, CardHeader, StatCard } from '@/components/ui/card';
import { getStats } from '@/lib/api';
import { APPROVAL_STATES, type Stats } from '@/lib/types';

/**
 * Overview. Every figure comes from `GET /console/api/stats`, which reshapes
 * the same `CollectorRegistry` `/metrics` serves and runs the same
 * `count_by_state()` query the `realguard_approval_queue_depth` gauge runs
 * (ADR 0014 §2 — "no new measurement"). Nothing on this page is computed
 * client-side from anything else.
 */
export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getStats()
      .then((next) => {
        setStats(next);
        setError(null);
      })
      .catch((caught: Error) => setError(caught.message));
  }, []);

  useEffect(load, [load]);

  if (error) {
    return (
      <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
        {error}
      </p>
    );
  }

  if (!stats) {
    return <p className="text-sm text-muted">Loading…</p>;
  }

  const nonZeroStates = APPROVAL_STATES.filter((s) => stats.approvals_by_state[s] > 0);

  return (
    <div className="space-y-6" data-testid="overview">
      <div>
        <h1 className="text-lg font-semibold text-ink">Overview</h1>
        <p className="mt-1 text-sm text-muted">
          Live counters for this firewall process
          {stats.policy_version ? (
            <>
              {' '}
              · policy{' '}
              <code className="font-mono text-xs">{stats.policy_version.slice(0, 19)}…</code>
            </>
          ) : null}
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Pending approvals"
          value={stats.totals.pending}
          tone={stats.totals.pending > 0 ? 'warn' : 'default'}
          caption="Held for human review"
        />
        <StatCard
          label="Approvals total"
          value={stats.totals.approvals}
          caption="All states, all time"
        />
        <StatCard
          label="Policy decisions"
          value={stats.totals.decisions}
          caption="realguard_decisions_total"
        />
        <StatCard
          label="HTTP requests"
          value={stats.totals.http_requests}
          caption="realguard_http_requests_total"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Decisions by verdict"
            subtitle="realguard_decisions_total, both planes"
          />
          <CardBody>
            <VerdictChart data={stats.decisions_by_verdict} />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Policy hits by rule"
            subtitle="realguard_policy_hits_total, top 8 rules"
          />
          <CardBody>
            <PolicyHitsChart data={stats.policy_hits} />
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Approval queue by state"
          subtitle="Live database counts — the same query the Prometheus gauge runs"
        />
        <CardBody>
          {nonZeroStates.length === 0 ? (
            <p className="text-sm text-muted">
              No approvals have been created yet. A request whose verdict is{' '}
              <code className="font-mono text-xs">NEED_APPROVAL</code> will appear here.
            </p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {nonZeroStates.map((state) => (
                <Badge key={state} tone={stateTone(state)}>
                  {state} · {stats.approvals_by_state[state]}
                </Badge>
              ))}
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
