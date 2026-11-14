'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { AlertOctagon, RotateCw } from 'lucide-react';

/** Route-level error boundary: keeps a rendering bug from blanking the war room. */
export default function RouteError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <main id="main" className="flex min-h-screen items-center justify-center px-4">
      <div role="alert" className="card w-full max-w-md p-8 text-center">
        <AlertOctagon className="mx-auto mb-4 h-10 w-10 text-red-300" aria-hidden="true" />
        <h1 className="text-xl font-semibold">Something went wrong</h1>
        <p className="mt-2 text-sm text-fg-muted">
          This view hit an unexpected error. Your incidents and approvals are safe on the server.
        </p>
        {error.digest && <p className="mt-2 font-mono text-2xs text-fg-subtle">Reference: {error.digest}</p>}
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <button type="button" onClick={reset} className="btn btn-primary">
            <RotateCw className="h-4 w-4" aria-hidden="true" />
            Try again
          </button>
          <Link href="/dashboard" className="btn btn-secondary">
            Back to dashboard
          </Link>
        </div>
      </div>
    </main>
  );
}
