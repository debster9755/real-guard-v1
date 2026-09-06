import type { Metadata } from 'next';

import { AuthProvider } from '@/components/auth-provider';
import { ThemeProvider } from '@/components/theme-provider';

import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'real-guard-v1 console',
    template: '%s — real-guard-v1 console',
  },
  description:
    'Reviewer console for real-guard-v1: the approval queue, decision history and policy-decision overview.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* An external file, not an inline snippet: SEC-008's CSP
            (`default-src 'self'`, no `unsafe-inline`) refuses inline
            scripts. See public/theme-init.js. */}
        <script src="/console/theme-init.js" />
      </head>
      <body className="min-h-full bg-canvas font-sans text-ink antialiased">
        <ThemeProvider>
          <AuthProvider>{children}</AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
