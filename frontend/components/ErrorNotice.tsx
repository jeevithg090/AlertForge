import Link from 'next/link';
import { ApiError } from '@/lib/api';

/** Inline error banner. A 401 links to the sign-in page instead of blaming the network. */
export default function ErrorNotice({ error, className = '' }: { error: unknown; className?: string }) {
  if (!error) return null;
  const unauthorized = error instanceof ApiError && error.status === 401;
  const message =
    error instanceof ApiError
      ? error.status === 0
        ? 'Cannot reach the SentinelForge API — is the backend running?'
        : error.message
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    <div
      role="alert"
      className={`bg-red-500/10 border border-red-500/40 text-red-300 rounded-lg p-4 text-sm ${className}`}
    >
      {unauthorized ? (
        <>
          Sign-in required.{' '}
          <Link href="/login" className="underline text-red-200 hover:text-white">
            Go to login
          </Link>
        </>
      ) : (
        message
      )}
    </div>
  );
}
