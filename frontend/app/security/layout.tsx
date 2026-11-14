import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Security Controls' };

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
