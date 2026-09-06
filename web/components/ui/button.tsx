'use client';

import clsx from 'clsx';
import type { ButtonHTMLAttributes } from 'react';

/**
 * Hand-rolled, in the spirit of shadcn/ui's composition pattern but without
 * the Radix dependency tree (ADR 0014: "keep it lean" — this console needs
 * six primitives, not a component library).
 */

type Variant = 'primary' | 'secondary' | 'ghost' | 'approve' | 'deny';
type Size = 'sm' | 'md';

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-brand text-brand-ink hover:opacity-90 disabled:opacity-50',
  secondary:
    'bg-surface text-ink border border-line hover:bg-elevated disabled:opacity-50',
  ghost: 'text-muted hover:bg-elevated hover:text-ink disabled:opacity-50',
  approve:
    'bg-ok text-white dark:text-canvas hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed',
  deny: 'bg-danger text-white dark:text-canvas hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed',
};

const SIZES: Record<Size, string> = {
  sm: 'h-8 px-3 text-xs',
  md: 'h-10 px-4 text-sm',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export function Button({
  variant = 'primary',
  size = 'md',
  className,
  type = 'button',
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={clsx(
        'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...props}
    />
  );
}
