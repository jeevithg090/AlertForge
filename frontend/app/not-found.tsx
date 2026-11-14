import type { Metadata } from 'next';
import Link from 'next/link';
import { Compass } from 'lucide-react';
import Logo from '@/components/Logo';

export const metadata: Metadata = { title: 'Page not found' };

export default function NotFound() {
  return (
    <main id="main" className="flex min-h-screen items-center justify-center px-4">
      <div className="card w-full max-w-md p-8 text-center">
        <div className="mx-auto mb-4 flex justify-center">
          <Logo className="h-10 w-10" />
        </div>
        <p className="eyebrow">Error 404</p>
        <h1 className="mt-2 text-2xl font-semibold">This page isn&apos;t on the watch list</h1>
        <p className="mt-2 text-sm text-fg-muted">
          The address may be mistyped, or the page was moved. Head back to the war room to see live incidents.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <Link href="/dashboard" className="btn btn-primary">
            <Compass className="h-4 w-4" aria-hidden="true" />
            Go to dashboard
          </Link>
          <Link href="/analytics" className="btn btn-secondary">
            View analytics
          </Link>
        </div>
      </div>
    </main>
  );
}
