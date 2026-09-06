'use client';

import clsx from 'clsx';

/** A single-row tab filter. Rendered as real <button>s in a `tablist`, so
 *  keyboard and screen-reader users get the semantics for free. */
export function Tabs({
  tabs,
  active,
  onChange,
  counts,
}: {
  tabs: readonly string[];
  active: string;
  onChange: (tab: string) => void;
  counts?: Record<string, number>;
}) {
  return (
    <div role="tablist" aria-label="Approval status filter" className="flex flex-wrap gap-1">
      {tabs.map((tab) => {
        const selected = tab === active;
        const count = counts?.[tab];
        return (
          <button
            key={tab}
            role="tab"
            type="button"
            aria-selected={selected}
            data-testid={`tab-${tab}`}
            onClick={() => onChange(tab)}
            className={clsx(
              'rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition-colors',
              selected
                ? 'bg-brand text-brand-ink'
                : 'text-muted hover:bg-elevated hover:text-ink',
            )}
          >
            {tab}
            {typeof count === 'number' ? (
              <span className={clsx('ml-1.5 tabular-nums', selected ? 'opacity-80' : 'opacity-60')}>
                {count}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
