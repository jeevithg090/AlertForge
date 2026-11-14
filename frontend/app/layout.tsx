import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'SentinelForge — Autonomous SOC War Room',
    template: '%s · SentinelForge',
  },
  description:
    'Specialist agents triage, investigate and contain security alerts, with a human approver in the loop for every irreversible action.',
  applicationName: 'SentinelForge',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0A0E1A',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
