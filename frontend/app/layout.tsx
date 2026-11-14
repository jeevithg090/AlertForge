import type { Metadata, Viewport } from 'next';
import './globals.css';

const description =
  'Specialist agents triage, investigate and contain security alerts, with a human approver in the loop for every irreversible action.';

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000'),
  title: {
    default: 'SentinelForge — Autonomous SOC War Room',
    template: '%s · SentinelForge',
  },
  description,
  applicationName: 'SentinelForge',
  robots: { index: false, follow: false },
  openGraph: {
    type: 'website',
    siteName: 'SentinelForge',
    title: 'SentinelForge — Autonomous SOC War Room',
    description,
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SentinelForge — Autonomous SOC War Room',
    description,
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0A0E1A',
  colorScheme: 'dark',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
