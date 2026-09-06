import type { Config } from 'tailwindcss';

/**
 * real-guard-v1 console design tokens.
 *
 * Every colour is an `R G B` triplet custom property defined in
 * `app/globals.css` (once for light, once under `.dark`), consumed here
 * through `rgb(var(--…) / <alpha-value>)` so Tailwind's opacity modifiers
 * (`bg-surface/60`) keep working. That indirection exists for two reasons:
 * the `dark:` variant then needs no parallel colour scale, and the recharts
 * charts can read the exact same tokens at runtime via
 * `getComputedStyle(document.documentElement)` rather than hardcoding a
 * second, drift-prone palette in TypeScript.
 *
 * The palette is this project's own — indigo/violet brand on slate surfaces,
 * with amber for "held for review", emerald for approved/allowed and rose
 * for denied. It is deliberately *not* sentinelforge's teal-on-near-black
 * (a different product by the same author, cited in ADR 0014 as inspiration
 * for the composition patterns, never as a source of literal styling).
 */
const config: Config = {
  darkMode: 'class',
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        canvas: 'rgb(var(--rg-canvas) / <alpha-value>)',
        surface: 'rgb(var(--rg-surface) / <alpha-value>)',
        elevated: 'rgb(var(--rg-elevated) / <alpha-value>)',
        line: 'rgb(var(--rg-line) / <alpha-value>)',
        ink: 'rgb(var(--rg-ink) / <alpha-value>)',
        muted: 'rgb(var(--rg-muted) / <alpha-value>)',
        brand: {
          DEFAULT: 'rgb(var(--rg-brand) / <alpha-value>)',
          soft: 'rgb(var(--rg-brand-soft) / <alpha-value>)',
          ink: 'rgb(var(--rg-brand-ink) / <alpha-value>)',
        },
        ok: 'rgb(var(--rg-ok) / <alpha-value>)',
        warn: 'rgb(var(--rg-warn) / <alpha-value>)',
        danger: 'rgb(var(--rg-danger) / <alpha-value>)',
        info: 'rgb(var(--rg-info) / <alpha-value>)',
      },
      fontFamily: {
        // No `next/font`: it injects an inline <style> block, which
        // app/main.py's `Content-Security-Policy: default-src 'self'`
        // (SEC-008, no unsafe-inline) refuses — and no webfont is fetched
        // from a CDN either (SPEC.md §2.19). System stacks only.
        sans: [
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'SF Mono',
          'Menlo',
          'Consolas',
          'Liberation Mono',
          'monospace',
        ],
      },
      borderRadius: {
        xl: '0.75rem',
        '2xl': '1rem',
      },
      boxShadow: {
        card: '0 1px 2px rgb(15 23 42 / 0.04), 0 8px 24px rgb(15 23 42 / 0.06)',
      },
    },
  },
  plugins: [],
};

export default config;
