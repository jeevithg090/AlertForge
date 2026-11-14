import Link from 'next/link';
import { AlertTriangle, LogIn, RotateCw } from 'lucide-react';
import { ApiError } from '@/lib/api';

/** Turn any thrown value into a sentence an operator can act on. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 0) return 'Cannot reach the SentinelForge API. Check that the backend is running.';
    if (error.status === 401) return 'Your session is missing or has expired. Sign in to continue.';
    if (error.status === 403) return 'Your role does not have permission for this.';
    if (error.status === 404) return 'That item does not exist or was removed.';
    if (error.status >= 500) return `The server hit an error (${error.status}). Try again in a moment.`;
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Inline error banner. A 401 links to the sign-in page instead of blaming the
 * network; pass `onRetry` to offer a retry button.
 */
export default function ErrorNotice({
  error,
  className = '',
  onRetry,
}: {
  error: unknown;
  className?: string;
  onRetry?: () => void;
}) {
  if (!error) return null;
  const unauthorized = error instanceof ApiError && error.status === 401;
  return (
    <div
      role="alert"
      className={`flex flex-wrap items-start gap-3 rounded-xl border border-red-400/40 bg-red-500/10 p-4 text-sm text-red-200 ${className}`}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-300" aria-hidden="true" />
      <p className="min-w-0 flex-1">{describeError(error)}</p>
      {unauthorized ? (
        <Link href="/login" className="btn btn-danger btn-sm">
          <LogIn className="h-3.5 w-3.5" aria-hidden="true" />
          Sign in
        </Link>
      ) : (
        onRetry && (
          <button type="button" onClick={onRetry} className="btn btn-danger btn-sm">
            <RotateCw className="h-3.5 w-3.5" aria-hidden="true" />
            Retry
          </button>
        )
      )}
    </div>
  );
}
