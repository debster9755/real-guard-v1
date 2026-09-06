import clsx from 'clsx';
import type { ReactNode } from 'react';

export function Card({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={clsx(
        'rounded-xl border border-line bg-surface shadow-card',
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
      <div>
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {subtitle ? <p className="mt-0.5 text-xs text-muted">{subtitle}</p> : null}
      </div>
      {action}
    </div>
  );
}

export function CardBody({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return <div className={clsx('px-5 py-4', className)}>{children}</div>;
}

/** An overview tile: one number, its label, and an optional caption that
 *  says where the number came from (this console never shows a figure whose
 *  provenance it cannot name — ADR 0014 §2's "no new measurement"). */
export function StatCard({
  label,
  value,
  caption,
  tone = 'default',
}: {
  label: string;
  value: number | string;
  caption?: string;
  tone?: 'default' | 'warn' | 'ok' | 'danger';
}) {
  const toneClass = {
    default: 'text-ink',
    warn: 'text-warn',
    ok: 'text-ok',
    danger: 'text-danger',
  }[tone];

  return (
    <Card className="p-5">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-muted">
        {label}
      </p>
      <p className={clsx('mt-2 text-3xl font-semibold tabular-nums', toneClass)}>
        {value}
      </p>
      {caption ? <p className="mt-1 text-xs text-muted">{caption}</p> : null}
    </Card>
  );
}
