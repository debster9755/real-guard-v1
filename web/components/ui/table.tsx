import clsx from 'clsx';
import type { ReactNode, ThHTMLAttributes } from 'react';

/** A plain semantic table. Horizontal overflow scrolls inside its own
 *  container so a wide row never makes the whole page scroll sideways. */
export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">{children}</table>
    </div>
  );
}

export function Th({
  className,
  children,
  ...props
}: ThHTMLAttributes<HTMLTableCellElement> & { children: ReactNode }) {
  return (
    <th
      scope="col"
      className={clsx(
        'whitespace-nowrap border-b border-line px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-muted',
        className,
      )}
      {...props}
    >
      {children}
    </th>
  );
}

export function Td({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <td className={clsx('border-b border-line px-4 py-3 align-top text-ink', className)}>
      {children}
    </td>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-10 text-center text-sm text-muted">
        {children}
      </td>
    </tr>
  );
}
