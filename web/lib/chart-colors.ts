'use client';

import { useEffect, useState } from 'react';

import { useTheme } from '@/components/theme-provider';

/**
 * Reads the live design tokens off `<html>` so recharts draws in exactly the
 * palette the rest of the page uses, in whichever theme is active.
 *
 * recharts sets `fill`/`stroke` as SVG *attributes* on each generated shape,
 * and an SVG presentation attribute does not resolve `var(--…)` — so a
 * Tailwind class on the chart layer cannot colour the bars. Reading the
 * computed values once per theme change and passing real colour strings is
 * the honest way to keep one source of truth (app/globals.css) rather than
 * hardcoding a second, drift-prone palette here.
 */

const TOKENS = ['--rg-brand', '--rg-ok', '--rg-warn', '--rg-danger', '--rg-info', '--rg-muted', '--rg-line'] as const;

type Token = (typeof TOKENS)[number];

export type ChartColors = Record<Token, string>;

const FALLBACK: ChartColors = {
  '--rg-brand': 'rgb(79 70 229)',
  '--rg-ok': 'rgb(4 120 87)',
  '--rg-warn': 'rgb(180 83 9)',
  '--rg-danger': 'rgb(190 18 60)',
  '--rg-info': 'rgb(3 105 161)',
  '--rg-muted': 'rgb(82 98 122)',
  '--rg-line': 'rgb(226 232 240)',
};

export function useChartColors(): ChartColors {
  const { theme } = useTheme();
  const [colors, setColors] = useState<ChartColors>(FALLBACK);

  useEffect(() => {
    const computed = getComputedStyle(document.documentElement);
    const next = { ...FALLBACK };
    for (const token of TOKENS) {
      const triplet = computed.getPropertyValue(token).trim();
      if (triplet) next[token] = `rgb(${triplet})`;
    }
    setColors(next);
  }, [theme]);

  return colors;
}

/** A verdict's own colour, so ALLOW/DENY/NEED_APPROVAL read the same way in
 *  the chart as they do in the badges elsewhere in the console. */
export function verdictColor(verdict: string, colors: ChartColors): string {
  switch (verdict) {
    case 'ALLOW':
      return colors['--rg-ok'];
    case 'DENY':
      return colors['--rg-danger'];
    case 'NEED_APPROVAL':
      return colors['--rg-warn'];
    default:
      return colors['--rg-info'];
  }
}
