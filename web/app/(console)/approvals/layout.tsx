import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Approval queue' };

export default function ApprovalsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
