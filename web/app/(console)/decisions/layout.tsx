import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Decision history' };

export default function DecisionsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
