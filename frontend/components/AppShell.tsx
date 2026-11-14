'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { BarChart3, LayoutDashboard, LogIn, LogOut, ShieldCheck } from 'lucide-react';
import clsx from 'clsx';
import Logo from './Logo';
import { type Session, getSession, logout } from '@/lib/api';

const NAV = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/analytics', label: 'Analytics', icon: BarChart3 },
  { href: '/security', label: 'Security', icon: ShieldCheck },
];

/**
 * Shared page chrome: skip link, brand, primary navigation with the current
 * page marked, an optional status slot (e.g. the live-stream indicator) and the
 * signed-in operator.
 */
export default function AppShell({ children, status }: { children: ReactNode; status?: ReactNode }) {
  const pathname = usePathname() || '';
  const router = useRouter();
  // Read the session after mount so server and client markup match.
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  useEffect(() => setSession(getSession()), []);

  const signOut = () => {
    logout();
    setSession(null);
    router.push('/login');
  };

  return (
    <div className="min-h-screen">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <header className="sticky top-0 z-30 border-b border-line bg-canvas/85 backdrop-blur supports-[backdrop-filter]:bg-canvas/70">
        <div className="container-page flex flex-wrap items-center gap-x-4 gap-y-2 py-3">
          <Link href="/dashboard" className="flex items-center gap-2.5 rounded-lg pr-2" aria-label="SentinelForge home">
            <Logo />
            <span className="leading-tight">
              <span className="block text-sm font-bold tracking-wide text-fg">SentinelForge</span>
              <span className="hidden text-2xs text-fg-subtle sm:block">SOC War Room</span>
            </span>
          </Link>

          <div className="ml-auto flex items-center gap-2 md:order-last">
            {status}
            {session === undefined ? null : session ? (
              <div className="flex items-center gap-2">
                <span className="hidden text-right leading-tight lg:block">
                  <span className="block text-xs font-medium text-fg">{session.name || session.email}</span>
                  <span className="block text-2xs capitalize text-fg-subtle">{session.role}</span>
                </span>
                <button type="button" onClick={signOut} className="btn btn-ghost btn-sm" aria-label="Sign out">
                  <LogOut className="h-4 w-4" aria-hidden="true" />
                  <span className="hidden sm:inline">Sign out</span>
                </button>
              </div>
            ) : (
              <Link href={`/login?next=${encodeURIComponent(pathname)}`} className="btn btn-secondary btn-sm">
                <LogIn className="h-4 w-4" aria-hidden="true" />
                Sign in
              </Link>
            )}
          </div>

          <nav aria-label="Primary" className="-mx-1 flex w-full items-center gap-1 overflow-x-auto md:mx-0 md:w-auto">
            {NAV.map(({ href, label, icon: Icon }) => {
              const active = pathname === href || pathname.startsWith(`${href}/`) || (href === '/dashboard' && pathname.startsWith('/incidents'));
              return (
                <Link key={href} href={href} aria-current={active ? 'page' : undefined} className={clsx('nav-link gap-2')}>
                  <Icon className="h-4 w-4" aria-hidden="true" />
                  {label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="container-page py-6 focus:outline-none sm:py-8">
        {children}
      </main>
    </div>
  );
}
