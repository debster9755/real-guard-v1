import type { Metadata } from 'next';

import { ConsoleShell } from '@/components/console-shell';

/**
 * A route group — `(console)` is parentheses-wrapped, so it adds nothing to
 * the URL. Its children are `/console/`, `/console/approvals/` and
 * `/console/decisions/` (the `/console` prefix comes from `basePath` in
 * next.config.ts); `/console/login/` deliberately sits outside this group,
 * so it renders without the signed-in chrome and without the route guard.
 *
 * A server component, so it can export `metadata`; the shell it renders is
 * the client component.
 */
export const metadata: Metadata = { title: 'Overview' };

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  return <ConsoleShell>{children}</ConsoleShell>;
}
