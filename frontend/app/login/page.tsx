'use client';

import { Suspense, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ArrowLeft, Eye, EyeOff, LogIn } from 'lucide-react';
import Logo from '@/components/Logo';
import { Spinner } from '@/components/ui';
import { ApiError, login } from '@/lib/api';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Only follow same-site relative paths after sign-in (no open redirects). */
function safeNext(next: string | null): string {
  if (next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/login')) return next;
  return '/dashboard';
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState({ email: false, password: false });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const emailError = !email ? 'Enter your email address.' : !EMAIL_RE.test(email) ? 'Enter a valid email, like name@company.com.' : '';
  const passwordError = !password ? 'Enter your password.' : '';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched({ email: true, password: true });
    if (emailError || passwordError) return;
    setError('');
    setLoading(true);
    try {
      await login(email.trim(), password);
      router.push(safeNext(params.get('next')));
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 401) setError('That email and password don’t match an operator account.');
      else if (err instanceof ApiError && err.status === 0) setError('Cannot reach the SentinelForge API. Check that the backend is running.');
      else setError(err instanceof Error ? err.message : 'Sign-in failed. Try again.');
      setLoading(false);
    }
  };

  const showEmailError = touched.email && emailError;
  const showPasswordError = touched.password && passwordError;

  return (
    <main id="main" className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <Logo className="h-12 w-12" />
          <h1 className="mt-4 text-2xl font-semibold">Sign in to SentinelForge</h1>
          <p className="mt-1 text-sm text-fg-muted">Operator access to the SOC war room</p>
        </div>

        <div className="card p-6 sm:p-7">
          {error && (
            <div role="alert" className="mb-4 rounded-lg border border-red-400/40 bg-red-500/10 p-3 text-sm text-red-200">
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            <div>
              <label htmlFor="email" className="label">
                Email
              </label>
              <input
                id="email"
                name="email"
                autoComplete="username"
                inputMode="email"
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onBlur={() => setTouched(t => ({ ...t, email: true }))}
                placeholder="you@company.com"
                className="input"
                aria-invalid={showEmailError ? true : undefined}
                aria-describedby={showEmailError ? 'email-error' : undefined}
                required
              />
              {showEmailError && (
                <p id="email-error" className="field-error">
                  {emailError}
                </p>
              )}
            </div>
            <div>
              <label htmlFor="password" className="label">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  name="password"
                  autoComplete="current-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onBlur={() => setTouched(t => ({ ...t, password: true }))}
                  className="input pr-11"
                  aria-invalid={showPasswordError ? true : undefined}
                  aria-describedby={showPasswordError ? 'password-error' : undefined}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-lg text-fg-subtle hover:text-fg"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                </button>
              </div>
              {showPasswordError && (
                <p id="password-error" className="field-error">
                  {passwordError}
                </p>
              )}
            </div>
            <button type="submit" disabled={loading} className="btn btn-primary w-full">
              {loading ? (
                <Spinner label="Signing in…" />
              ) : (
                <>
                  <LogIn className="h-4 w-4" aria-hidden="true" />
                  Sign in
                </>
              )}
            </button>
          </form>
        </div>

        <p className="mt-6 text-center text-xs text-fg-subtle">
          Accounts are managed by your SentinelForge administrator.
        </p>
        <div className="mt-3 text-center">
          <Link href="/dashboard" className="inline-flex items-center gap-1 text-sm text-fg-muted hover:text-fg">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            Back to dashboard
          </Link>
        </div>
      </div>
    </main>
  );
}

export default function LoginPage() {
  // useSearchParams needs a Suspense boundary for static prerendering.
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}
