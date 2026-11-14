'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import { CheckCircle2, AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import { type ApiRecord, fetchSecurityControls, fetchSecurityEvents } from '@/lib/api';
import { formatDateTime, humanize } from '@/lib/format';
import AppShell from '@/components/AppShell';
import ErrorNotice from '@/components/ErrorNotice';
import { Card, EmptyState, LoadingBlock, PageHeader, Skeleton } from '@/components/ui';

interface SecurityEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  details: ApiRecord | null;
}
interface Control {
  category: string;
  label: string;
  status: 'active' | 'inactive' | 'configured_dev_only';
  note?: string;
}

const CONTROL_STATUS: Record<string, { label: string; className: string }> = {
  active: { label: 'Active', className: 'border-warroom-success/40 bg-warroom-success/10 text-warroom-success' },
  configured_dev_only: { label: 'Dev only', className: 'border-warroom-warning/40 bg-warroom-warning/10 text-warroom-warning' },
  inactive: { label: 'Inactive', className: 'border-red-400/40 bg-red-500/10 text-red-300' },
};

export default function SecurityPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [controls, setControls] = useState<Control[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const onError = (err: unknown) => setError(err);
    Promise.all([
      fetchSecurityEvents(50).then(d => setEvents((d.events || []) as SecurityEvent[])).catch(onError),
      fetchSecurityControls().then(d => setControls((d.controls || []) as Control[])).catch(onError),
    ]).finally(() => setLoading(false));
  }, []);

  useEffect(load, [load]);

  const grouped = useMemo(() => {
    const g: Record<string, Control[]> = {};
    controls.forEach(c => (g[c.category] ||= []).push(c));
    return g;
  }, [controls]);
  const activeCount = controls.filter(c => c.status === 'active').length;

  return (
    <AppShell>
      <PageHeader
        title="Security controls"
        description="Guardrails that protect the agents themselves: input sanitisation, prompt-injection detection, RBAC, approvals and the tamper-evident audit log."
        actions={
          !loading && controls.length > 0 ? (
            <span className="badge border-warroom-success/40 bg-warroom-success/10 px-3 py-1 text-xs text-warroom-success">
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              {activeCount} of {controls.length} active
            </span>
          ) : undefined
        }
      />

      <ErrorNotice error={error} onRetry={load} className="mb-6" />

      {loading ? (
        <LoadingBlock label="Loading security controls">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {[0, 1, 2, 3].map(i => <Skeleton key={i} className="h-40 rounded-xl" />)}
          </div>
        </LoadingBlock>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
          <div className="grid grid-cols-1 content-start gap-4 md:grid-cols-2 lg:col-span-3">
            {Object.entries(grouped).map(([category, items]) => (
              <Card key={category} title={category} titleId={`ctl-${category.replace(/\W+/g, '-')}`}>
                <ul className="space-y-3 text-sm">
                  {items.map((c, i) => {
                    const meta = CONTROL_STATUS[c.status] ?? CONTROL_STATUS.inactive;
                    return (
                      <li key={i} className="flex items-start gap-2.5">
                        {c.status === 'active' ? (
                          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-warroom-success" aria-hidden="true" />
                        ) : (
                          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warroom-warning" aria-hidden="true" />
                        )}
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-fg">{c.label}</span>
                            {c.status !== 'active' && <span className={clsx('badge', meta.className)}>{meta.label}</span>}
                          </div>
                          {c.note && <p className="mt-0.5 text-xs text-fg-subtle">{c.note}</p>}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </Card>
            ))}
            {controls.length === 0 && !error && (
              <EmptyState title="No controls reported" className="md:col-span-2">
                The backend did not return any security controls.
              </EmptyState>
            )}
          </div>

          <Card
            title="Recent security events"
            icon={<ShieldAlert className="h-4 w-4" />}
            titleId="sec-events-heading"
            className="lg:col-span-2 lg:self-start"
          >
            {events.length === 0 ? (
              <EmptyState title="No security events yet" className="border-0 px-2 py-6">
                Submit an alert containing{' '}
                <code className="rounded bg-surface-raised px-1 py-0.5 text-xs text-fg">ignore previous instructions</code> to see
                PromptGuard block it.
              </EmptyState>
            ) : (
              <ol className="space-y-4">
                {events.map(ev => (
                  <li key={ev.id} className="border-l-2 border-warroom-warning/60 pl-3">
                    <div className="text-sm font-medium text-fg">{humanize(ev.action)}</div>
                    <div className="mt-0.5 flex flex-wrap gap-x-2 text-2xs text-fg-subtle">
                      <time dateTime={ev.timestamp}>{formatDateTime(ev.timestamp)}</time>
                      {ev.actor && <span>· {ev.actor}</span>}
                    </div>
                    {(ev.details?.reason || ev.details?.threat) && (
                      <p className="mt-1 break-words text-xs text-fg-muted">{ev.details?.threat || ev.details?.reason}</p>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </div>
      )}
    </AppShell>
  );
}
