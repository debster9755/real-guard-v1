'use client';

import { useEffect, type ReactNode } from 'react';

/**
 * A minimal dialog: a backdrop, Escape-to-close, focus-visible-friendly
 * controls, and `aria-modal`. Not a Radix `Dialog` — this console needs one
 * modal, and one modal does not justify the dependency (ADR 0014).
 *
 * Deliberately *not* a focus trap: implementing a correct one by hand is
 * more subtle than it looks, and a half-correct trap is worse for keyboard
 * users than none. Named here as a known limitation rather than left
 * unmentioned.
 */
export function Modal({
  open,
  title,
  onClose,
  children,
  footer,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink/40 p-4 backdrop-blur-sm sm:p-8"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        data-testid="review-modal"
        className="w-full max-w-3xl rounded-xl border border-line bg-surface shadow-card"
      >
        <div className="flex items-center justify-between gap-4 border-b border-line px-5 py-4">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            data-testid="modal-close"
            className="rounded-md px-2 py-1 text-lg leading-none text-muted hover:bg-elevated hover:text-ink"
          >
            &times;
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer ? (
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line px-5 py-4">
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}
