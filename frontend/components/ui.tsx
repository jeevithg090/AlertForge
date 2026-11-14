import clsx from 'clsx';
import type { ReactNode } from 'react';
import { SEVERITY_META, STATUS_META, VERDICT_META, humanize } from '@/lib/format';

/* ------------------------------------------------------------------ Card */

export function Card({
  title,
  icon,
  action,
  children,
  className,
  bodyClassName,
  as: Tag = 'section',
  titleId,
}: {
  title?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  as?: 'section' | 'div' | 'aside';
  titleId?: string;
}) {
  return (
    <Tag className={clsx('card', className)} aria-labelledby={title && titleId ? titleId : undefined}>
      {title && (
        <div className="card-header">
          <h2 id={titleId} className="card-title flex items-center gap-2">
            {icon && (
              <span className="text-fg-subtle" aria-hidden="true">
                {icon}
              </span>
            )}
            {title}
          </h2>
          {action}
        </div>
      )}
      <div className={clsx('card-body', bodyClassName)}>{children}</div>
    </Tag>
  );
}

/* ---------------------------------------------------------------- Badges */

export function SeverityBadge({ severity, className }: { severity?: string; className?: string }) {
  if (!severity) return null;
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={clsx('badge font-mono', meta?.className ?? 'border-line-strong bg-surface-raised text-fg-muted', className)}
      title={`Severity ${severity}`}
    >
      {meta ? `${meta.short} · ${meta.label}` : severity}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict?: string }) {
  if (!verdict) return null;
  const meta = VERDICT_META[verdict] ?? VERDICT_META.UNKNOWN;
  return <span className={clsx('badge', meta.className)}>{VERDICT_META[verdict]?.label ?? humanize(verdict)}</span>;
}

export function StatusText({ status, className }: { status?: string; className?: string }) {
  if (!status) return null;
  const meta = STATUS_META[status];
  const awaiting = status === 'AWAITING_APPROVAL';
  return (
    <span className={clsx('inline-flex items-center gap-1.5 text-xs font-medium', meta?.className ?? 'text-fg-muted', className)}>
      <span
        aria-hidden="true"
        className={clsx('h-1.5 w-1.5 rounded-full bg-current', awaiting && 'animate-pulse-dot')}
      />
      {meta?.label ?? humanize(status)}
    </span>
  );
}

export function CountBadge({ count, title }: { count: number; title?: string }) {
  return (
    <span
      className="badge border-warroom-anlst/40 bg-warroom-anlst/10 font-mono text-warroom-anlst"
      title={title}
    >
      ×{count}
    </span>
  );
}

/* ------------------------------------------------------- Live indicator */

export function LiveIndicator({ connected, compact = false }: { connected: boolean; compact?: boolean }) {
  const label = connected ? 'Live' : 'Offline';
  return (
    <span
      role="status"
      aria-live="polite"
      title={connected ? 'Live stream connected' : 'Live stream disconnected — retrying'}
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-2xs font-semibold',
        connected
          ? 'border-warroom-success/30 bg-warroom-success/10 text-warroom-success'
          : 'border-red-400/30 bg-red-500/10 text-red-300',
      )}
    >
      <span
        aria-hidden="true"
        className={clsx('h-1.5 w-1.5 rounded-full', connected ? 'bg-warroom-success animate-pulse-dot' : 'bg-red-400')}
      />
      <span className={clsx(compact && 'sr-only sm:not-sr-only')}>{label}</span>
      <span className="sr-only">{connected ? ' — live stream connected' : ' — live stream disconnected'}</span>
    </span>
  );
}

/* ---------------------------------------------------- Loading & empty */

export function Spinner({ className, label }: { className?: string; label?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
        <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      {label && <span>{label}</span>}
    </span>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx('skeleton', className)} aria-hidden="true" />;
}

export function LoadingBlock({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      {children}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  children,
  action,
  className,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center rounded-xl border border-dashed border-line-strong px-6 py-10 text-center',
        className,
      )}
    >
      {icon && (
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-surface-raised text-fg-muted" aria-hidden="true">
          {icon}
        </div>
      )}
      <p className="text-sm font-semibold text-fg">{title}</p>
      {children && <div className="mt-1 max-w-sm text-sm text-fg-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/* ---------------------------------------------------------- Stat tile */

export function Stat({
  label,
  value,
  tone = 'text-fg',
  hint,
}: {
  label: string;
  value: ReactNode;
  tone?: string;
  hint?: ReactNode;
}) {
  return (
    <div className="card p-4">
      <div className="eyebrow">{label}</div>
      <div className={clsx('mt-1 text-2xl font-semibold tabular-nums', tone)}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-fg-subtle">{hint}</div>}
    </div>
  );
}

/* --------------------------------------------------------- Page header */

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  eyebrow?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1">{eyebrow}</div>}
        <h1 className="text-xl font-semibold sm:text-2xl">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-fg-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
