import clsx from 'clsx';
import type { ReactNode } from 'react';

type Tone = 'neutral' | 'brand' | 'ok' | 'warn' | 'danger' | 'info';

const TONES: Record<Tone, string> = {
  neutral: 'border-line bg-elevated text-muted',
  brand: 'border-brand/30 bg-brand/10 text-brand',
  ok: 'border-ok/30 bg-ok/10 text-ok',
  warn: 'border-warn/30 bg-warn/10 text-warn',
  danger: 'border-danger/30 bg-danger/10 text-danger',
  info: 'border-info/30 bg-info/10 text-info',
};

export function Badge({
  tone = 'neutral',
  children,
  className,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium',
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/** SPEC.md §9.1's approval states, mapped to a consistent tone so the same
 *  state always reads the same way across the queue, the modal and the
 *  decision history. */
export function stateTone(state: string): Tone {
  switch (state) {
    case 'PENDING':
      return 'warn';
    case 'APPROVED':
    case 'COMPLETED':
      return 'ok';
    case 'DENIED':
    case 'FAILED':
      return 'danger';
    case 'RESUMING':
      return 'info';
    default:
      return 'neutral';
  }
}

/** SPEC.md's five risk levels. NONE/LOW are deliberately quiet; the eye
 *  should be drawn to HIGH and CRITICAL only. */
export function riskTone(level: string): Tone {
  switch (level) {
    case 'CRITICAL':
      return 'danger';
    case 'HIGH':
      return 'warn';
    case 'MEDIUM':
      return 'info';
    default:
      return 'neutral';
  }
}
