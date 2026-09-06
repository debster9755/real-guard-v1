'use client';

import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { useChartColors, verdictColor } from '@/lib/chart-colors';
import type { Series } from '@/lib/types';

/**
 * The two overview charts. recharts (MIT) is bundled into the static export
 * by Next — nothing is fetched from a CDN at request time (SPEC.md §2.19).
 *
 * Both are horizontal bars: the categories are policy rule ids and verdict
 * names, which are long, unevenly-sized labels that a vertical axis reads
 * far better than a rotated horizontal one.
 */

function EmptyChart({ message }: { message: string }) {
  return (
    <div className="grid h-[220px] place-items-center text-xs text-muted">{message}</div>
  );
}

export function VerdictChart({ data }: { data: Series[] }) {
  const colors = useChartColors();
  if (data.length === 0) {
    return <EmptyChart message="No decisions recorded yet in this process." />;
  }

  return (
    <div data-testid="chart-verdicts">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
          <XAxis
            type="number"
            allowDecimals={false}
            tick={{ fill: colors['--rg-muted'], fontSize: 11 }}
            stroke={colors['--rg-line']}
          />
          <YAxis
            type="category"
            dataKey="name"
            width={118}
            tick={{ fill: colors['--rg-muted'], fontSize: 11 }}
            stroke={colors['--rg-line']}
          />
          <Tooltip
            cursor={{ fill: colors['--rg-line'], fillOpacity: 0.35 }}
            contentStyle={{
              fontSize: 12,
              borderRadius: 8,
              border: `1px solid ${colors['--rg-line']}`,
            }}
          />
          <Bar
            dataKey="value"
            radius={[0, 4, 4, 0]}
            maxBarSize={26}
            // Off deliberately: recharts grows bars from zero width over
            // 1.5s by default, so a chart read (or screenshotted) right
            // after load shows empty axes. An operations console should
            // render its numbers immediately and identically every time.
            isAnimationActive={false}
          >
            {data.map((row) => (
              <Cell key={row.name} fill={verdictColor(row.name, colors)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function PolicyHitsChart({ data }: { data: Series[] }) {
  const colors = useChartColors();
  if (data.length === 0) {
    return <EmptyChart message="No policy rules have fired yet in this process." />;
  }

  const top = data.slice(0, 8);

  return (
    <div data-testid="chart-policy-hits">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={top} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
          <XAxis
            type="number"
            allowDecimals={false}
            tick={{ fill: colors['--rg-muted'], fontSize: 11 }}
            stroke={colors['--rg-line']}
          />
          <YAxis
            type="category"
            dataKey="name"
            width={150}
            tick={{ fill: colors['--rg-muted'], fontSize: 11 }}
            stroke={colors['--rg-line']}
          />
          <Tooltip
            cursor={{ fill: colors['--rg-line'], fillOpacity: 0.35 }}
            contentStyle={{
              fontSize: 12,
              borderRadius: 8,
              border: `1px solid ${colors['--rg-line']}`,
            }}
          />
          <Bar
            dataKey="value"
            fill={colors['--rg-brand']}
            radius={[0, 4, 4, 0]}
            maxBarSize={26}
            isAnimationActive={false}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
