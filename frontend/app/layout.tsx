import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SentinelForge — Autonomous SOC War Room',
  description: 'Multiple specialist AI agents triage, investigate, and contain security alerts — with a human commander in the loop for every irreversible action.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
