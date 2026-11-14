'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import clsx from 'clsx';
import { Activity, ChevronRight, Inbox, Radio, Search, Send, X } from 'lucide-react';
import { useAllIncidentsStream, type SSEEvent } from '@/lib/sse';
import { ApiError, type IncidentSummary, fetchIncidents, fetchPendingApprovals, ingestText } from '@/lib/api';
import { STATUS_META, formatDateTime, formatTime, timeAgo } from '@/lib/format';
import AppShell from '@/components/AppShell';
import ErrorNotice, { describeError } from '@/components/ErrorNotice';
import {
  Card,
  CountBadge,
  EmptyState,
  LiveIndicator,
  LoadingBlock,
  PageHeader,
  SeverityBadge,
  Skeleton,
  Spinner,
  Stat,
  StatusText,
} from '@/components/ui';

interface LogEntry {
  id: number;
  ts: string;
  event: SSEEvent;
}

type StatusFilter = 'all' | 'active' | 'approval' | 'closed';

const STATUS_FILTERS: { key: StatusFilter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'active', label: 'Active' },
  { key: 'approval', label: 'Needs approval' },
  { key: 'closed', label: 'Closed' },
];

const CLOSED = ['RESOLVED', 'DISMISSED'];

const EVENT_TYPE_COLORS: Record<string, string> = {
  'incident.created': 'text-emerald-300',
  'triage.started': 'text-sky-300',
  'triage.complete': 'text-sky-200',
  'investigation.started': 'text-cyan-300',
  'investigation.complete': 'text-cyan-200',
  'plan.generated': 'text-violet-300',
  'approval.required': 'text-warroom-warning',
  'approval.received': 'text-yellow-200',
  'step.executing': 'text-orange-300',
  'step.complete': 'text-emerald-300',
  'step.failed': 'text-red-300',
  'incident.resolved': 'text-warroom-success',
  'pir.complete': 'text-indigo-300',
  'thinking.chunk': 'text-violet-300',
  'rollback.triggered': 'text-red-300',
};

function matchesStatus(inc: IncidentSummary, f: StatusFilter) {
  if (f === 'active') return !CLOSED.includes(inc.status);
  if (f === 'approval') return inc.status === 'AWAITING_APPROVAL';
  if (f === 'closed') return CLOSED.includes(inc.status);
  return true;
}

export default function DashboardPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [approvalCount, setApprovalCount] = useState(0);
  const [eventLog, setEventLog] = useState<LogEntry[]>([]);
  const eventLogRef = useRef<HTMLDivElement>(null);
  const logSeq = useRef(0);

  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [severity, setSeverity] = useState('');
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(() => {
    setLoading(true);
    setLoadError(null);
    fetchIncidents()
      .then(data => setIncidents(data.incidents || []))
      .catch(setLoadError)
      .finally(() => setLoading(false));
    fetchPendingApprovals()
      .then(data => {
        // API returns { pending: [...], count: N } — not an array.
        if (data && typeof data.count === 'number') setApprovalCount(data.count);
      })
      .catch(() => {});
  }, []);

  useEffect(load, [load]);

  // Keep the "4m ago" labels fresh.
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(t);
  }, []);

  // Handle every live event (not just the latest render's) so bursts aren't dropped.
  const { connected } = useAllIncidentsStream((evt: SSEEvent) => {
    if (evt.type === 'incident.created' && evt.incident_id) {
      const newId: string = evt.incident_id;
      setIncidents(prev =>
        prev.some(i => i.id === newId)
          ? prev
          : [
              {
                id: newId,
                severity: evt.severity || 'P3_MEDIUM',
                status: 'INGESTED',
                affected_service: evt.affected_service || 'unknown',
                alert_message: evt.alert_message || '',
                created_at: new Date().toISOString(),
              },
              ...prev,
            ],
      );
    }
    // Reflect pipeline progress in the feed without a refetch.
    if (evt.incident_id) {
      const nextStatus: Record<string, string> = {
        'triage.started': 'TRIAGING',
        'investigation.started': 'INVESTIGATING',
        'plan.generated': 'PLANNING',
        'approval.required': 'AWAITING_APPROVAL',
        'step.executing': 'EXECUTING',
        'incident.resolved': 'RESOLVED',
      };
      const status = nextStatus[evt.type];
      if (status) setIncidents(prev => prev.map(i => (i.id === evt.incident_id ? { ...i, status } : i)));
    }
    if (evt.type === 'thinking.chunk') return; // too chatty for the log
    logSeq.current += 1;
    setEventLog(prev => [...prev.slice(-199), { id: logSeq.current, ts: new Date().toISOString(), event: evt }]);
  });

  useEffect(() => {
    if (eventLogRef.current) eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight;
  }, [eventLog]);

  const counts = useMemo(() => {
    const active = incidents.filter(i => !CLOSED.includes(i.status)).length;
    const awaiting = incidents.filter(i => i.status === 'AWAITING_APPROVAL').length;
    const resolved = incidents.filter(i => i.status === 'RESOLVED').length;
    const alerts = incidents.reduce((n, i) => n + (i.alert_count ?? 1), 0);
    return { active, awaiting, pendingSteps: approvalCount, resolved, alerts };
  }, [incidents, approvalCount]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return incidents.filter(
      i =>
        matchesStatus(i, statusFilter) &&
        (!severity || i.severity === severity) &&
        (!q ||
          i.id.toLowerCase().includes(q) ||
          i.affected_service?.toLowerCase().includes(q) ||
          i.alert_message?.toLowerCase().includes(q)),
    );
  }, [incidents, query, statusFilter, severity]);

  const filtersActive = query !== '' || statusFilter !== 'all' || severity !== '';
  const clearFilters = () => {
    setQuery('');
    setStatusFilter('all');
    setSeverity('');
  };

  return (
    <AppShell status={<LiveIndicator connected={connected} compact />}>
      <PageHeader
        title="Incident feed"
        description="Alerts are correlated into incidents, triaged and investigated by the agent team. Anything irreversible waits for your approval."
      />

      <div className="mb-6 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4" aria-label="Incident summary">
        <Stat label="Active incidents" value={loading ? '–' : counts.active} tone="text-red-300" />
        <Stat
          label="Awaiting approval"
          value={loading ? '–' : counts.awaiting}
          tone={counts.awaiting > 0 ? 'text-warroom-warning' : 'text-fg'}
          hint={loading || !counts.pendingSteps ? undefined : `${counts.pendingSteps} step${counts.pendingSteps === 1 ? '' : 's'} to review`}
        />
        <Stat label="Resolved" value={loading ? '–' : counts.resolved} tone="text-warroom-success" />
        <Stat
          label="Alerts correlated"
          value={loading ? '–' : counts.alerts}
          hint={loading ? undefined : `into ${incidents.length} incident${incidents.length === 1 ? '' : 's'}`}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Incident feed */}
        <section aria-labelledby="feed-heading" className="min-w-0 lg:col-span-2">
          <h2 id="feed-heading" className="sr-only">
            Incidents
          </h2>

          <div className="card mb-4 p-3 sm:p-4">
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <label htmlFor="incident-search" className="sr-only">
                  Search incidents
                </label>
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" aria-hidden="true" />
                <input
                  id="incident-search"
                  type="search"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  placeholder="Search service, message or ID"
                  className="input pl-9"
                />
              </div>
              <div className="sm:w-44">
                <label htmlFor="severity-filter" className="sr-only">
                  Filter by severity
                </label>
                <select id="severity-filter" value={severity} onChange={e => setSeverity(e.target.value)} className="input">
                  <option value="">All severities</option>
                  <option value="P1_CRITICAL">P1 · Critical</option>
                  <option value="P2_HIGH">P2 · High</option>
                  <option value="P3_MEDIUM">P3 · Medium</option>
                  <option value="P4_LOW">P4 · Low</option>
                </select>
              </div>
            </div>
            <div role="group" aria-label="Filter by status" className="mt-3 flex flex-wrap gap-2">
              {STATUS_FILTERS.map(f => (
                <button
                  key={f.key}
                  type="button"
                  aria-pressed={statusFilter === f.key}
                  onClick={() => setStatusFilter(f.key)}
                  className={clsx(
                    'btn btn-sm rounded-full',
                    statusFilter === f.key ? 'btn-accent' : 'btn-ghost border-line',
                  )}
                >
                  {f.label}
                  {f.key === 'approval' && counts.awaiting > 0 && (
                    <span className="rounded-full bg-warroom-warning/20 px-1.5 text-2xs text-warroom-warning">{counts.awaiting}</span>
                  )}
                </button>
              ))}
            </div>
          </div>

          <ErrorNotice error={loadError} onRetry={load} className="mb-4" />

          {loading ? (
            <LoadingBlock label="Loading incidents">
              <div className="space-y-3">
                {[0, 1, 2, 3].map(i => (
                  <div key={i} className="card space-y-3 p-4">
                    <div className="flex gap-2">
                      <Skeleton className="h-5 w-24" />
                      <Skeleton className="h-5 w-16" />
                    </div>
                    <Skeleton className="h-4 w-40" />
                    <Skeleton className="h-3 w-full" />
                  </div>
                ))}
              </div>
            </LoadingBlock>
          ) : !loadError && incidents.length === 0 ? (
            <EmptyState icon={<Inbox className="h-5 w-5" />} title="No incidents yet">
              Paste an alert in <span className="text-fg">Submit an alert</span>, or run{' '}
              <code className="rounded bg-surface-raised px-1 py-0.5 text-xs">make seed</code> to fire a demo scenario.
            </EmptyState>
          ) : !loadError && filtered.length === 0 ? (
            <EmptyState
              icon={<Search className="h-5 w-5" />}
              title="No incidents match these filters"
              action={
                <button type="button" onClick={clearFilters} className="btn btn-secondary btn-sm">
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                  Clear filters
                </button>
              }
            >
              Try a different search term or status.
            </EmptyState>
          ) : (
            <>
              {filtersActive && (
                <p className="mb-2 text-xs text-fg-subtle" aria-live="polite">
                  Showing {filtered.length} of {incidents.length} incidents
                </p>
              )}
              <ul className="space-y-3">
                {filtered.map(inc => (
                  <li key={inc.id}>
                    <IncidentRow incident={inc} now={now} />
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>

        {/* Sidebar */}
        <aside className="min-w-0 space-y-6" aria-label="Alert intake and live events">
          <QuickIngest />

          <Card
            title="Live event log"
            icon={<Radio className="h-4 w-4" />}
            titleId="event-log-heading"
            action={<LiveIndicator connected={connected} />}
            bodyClassName="p-0 sm:p-0"
          >
            <div
              ref={eventLogRef}
              className="max-h-[420px] space-y-0.5 overflow-y-auto p-2"
              aria-live="polite"
              aria-relevant="additions"
              tabIndex={0}
              aria-label="Live pipeline events"
            >
              {eventLog.length === 0 ? (
                <div className="flex flex-col items-center gap-2 px-4 py-8 text-center text-xs text-fg-subtle">
                  <Activity className="h-5 w-5" aria-hidden="true" />
                  {connected
                    ? 'Listening… pipeline events appear here as agents work.'
                    : 'Connecting to the live stream…'}
                </div>
              ) : (
                eventLog.map(entry => <EventLogRow key={entry.id} entry={entry} />)
              )}
            </div>
          </Card>
        </aside>
      </div>
    </AppShell>
  );
}

function IncidentRow({ incident: inc, now }: { incident: IncidentSummary; now: number }) {
  const awaiting = inc.status === 'AWAITING_APPROVAL';
  return (
    <Link
      href={`/incidents/${inc.id}`}
      className={clsx(
        'card group flex items-start gap-3 p-4 transition-colors duration-150 hover:border-warroom-tool/60 hover:bg-surface-raised animate-fade-in',
        awaiting && 'border-warroom-warning/50',
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={inc.severity} />
          <StatusText status={inc.status} />
          {(inc.alert_count ?? 1) > 1 && (
            <CountBadge count={inc.alert_count ?? 1} title="Correlated alerts folded into this incident" />
          )}
        </div>
        <div className="mt-2 flex flex-wrap items-baseline gap-x-2">
          <span className="font-semibold text-fg">{inc.affected_service}</span>
          <span className="font-mono text-2xs text-fg-subtle">#{inc.id.slice(0, 8)}</span>
        </div>
        <p className="mt-1 line-clamp-2 text-sm text-fg-muted">{inc.alert_message}</p>
        <time dateTime={inc.created_at} title={formatDateTime(inc.created_at)} className="mt-2 block text-2xs text-fg-subtle">
          {timeAgo(inc.created_at, now)} · {formatTime(inc.created_at)}
        </time>
      </div>
      <ChevronRight
        className="mt-1 h-4 w-4 shrink-0 text-fg-subtle transition-transform group-hover:translate-x-0.5 group-hover:text-fg"
        aria-hidden="true"
      />
      <span className="sr-only">
        Open incident {inc.id.slice(0, 8)}, {STATUS_META[inc.status]?.label ?? inc.status}
      </span>
    </Link>
  );
}

function EventLogRow({ entry }: { entry: LogEntry }) {
  const evt = entry.event;
  const detail = evt.text || evt.tool || evt.description || '';
  return (
    <div className="rounded-md px-2 py-1.5 text-xs transition-colors hover:bg-surface-raised">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <time className="font-mono text-2xs text-fg-subtle" dateTime={entry.ts}>
          {formatTime(entry.ts)}
        </time>
        <span className={clsx('font-mono font-semibold', EVENT_TYPE_COLORS[evt.type] || 'text-fg-muted')}>{evt.type}</span>
        {evt.persona && <span className="text-fg-subtle">[{evt.persona}]</span>}
        {evt.incident_id && (
          <Link href={`/incidents/${evt.incident_id}`} className="font-mono text-2xs text-fg-subtle underline-offset-2 hover:text-fg hover:underline">
            #{evt.incident_id.slice(0, 8)}
          </Link>
        )}
      </div>
      {detail && <p className="mt-0.5 truncate text-fg-muted">{String(detail)}</p>}
    </div>
  );
}

const SAMPLE_ALERT =
  'SIEM alert: 412 failed SSH logins from 203.0.113.45 against bastion-01 in 5 minutes, then a successful login as deploy.';

function QuickIngest() {
  const [text, setText] = useState('');
  const [touched, setTouched] = useState(false);
  const [state, setState] = useState<
    { kind: 'idle' } | { kind: 'sending' } | { kind: 'ok'; message: string; href?: string } | { kind: 'error'; message: string }
  >({ kind: 'idle' });

  const tooShort = text.trim().length > 0 && text.trim().length < 10;
  const invalid = touched && (text.trim().length === 0 || tooShort);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (text.trim().length < 10) return;
    setState({ kind: 'sending' });
    try {
      const data = await ingestText(text);
      if (!data.accepted) {
        setState({
          kind: 'error',
          message:
            data.reason === 'prompt_injection_blocked'
              ? 'Blocked by PromptGuard: the text looks like a prompt-injection attempt.'
              : `Not accepted: ${data.reason ?? 'unknown reason'}`,
        });
      } else if (data.correlated_into) {
        setState({
          kind: 'ok',
          message: `Correlated into existing incident #${data.correlated_into.slice(0, 8)}.`,
          href: `/incidents/${data.correlated_into}`,
        });
      } else {
        setState({
          kind: 'ok',
          message: `Incident #${data.incident_id?.slice(0, 8)} created. Agents are triaging it now.`,
          href: data.incident_id ? `/incidents/${data.incident_id}` : undefined,
        });
      }
      setText('');
      setTouched(false);
    } catch (err) {
      setState({ kind: 'error', message: err instanceof ApiError ? describeError(err) : 'Request failed. Try again.' });
    }
  };

  return (
    <Card title="Submit an alert" icon={<Send className="h-4 w-4" />} titleId="ingest-heading">
      <form onSubmit={submit} noValidate>
        <label htmlFor="quick-ingest" className="label">
          Alert text or JSON
        </label>
        <textarea
          id="quick-ingest"
          value={text}
          onChange={e => setText(e.target.value)}
          onBlur={() => text && setTouched(true)}
          placeholder="Paste a SIEM/EDR alert, e.g. “failed password for root from 193.32.162.144 …”"
          rows={4}
          className="input resize-y font-mono text-xs leading-relaxed"
          aria-invalid={invalid ? true : undefined}
          aria-describedby="quick-ingest-help"
        />
        <p id="quick-ingest-help" className={invalid ? 'field-error' : 'field-hint'}>
          {invalid
            ? 'Paste at least 10 characters so the triage agent has something to work with.'
            : 'Similar alerts are folded into an existing incident automatically.'}
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="submit" disabled={state.kind === 'sending'} className="btn btn-primary flex-1">
            {state.kind === 'sending' ? <Spinner label="Submitting…" /> : 'Submit alert'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => setText(SAMPLE_ALERT)}>
            Use example
          </button>
        </div>
        <div aria-live="polite" className="empty:hidden">
          {state.kind === 'ok' && (
            <p className="mt-3 rounded-lg border border-warroom-success/30 bg-warroom-success/10 p-3 text-xs text-emerald-200">
              {state.message}{' '}
              {state.href && (
                <Link href={state.href} className="font-semibold text-warroom-success underline underline-offset-2">
                  Open
                </Link>
              )}
            </p>
          )}
          {state.kind === 'error' && (
            <p role="alert" className="mt-3 rounded-lg border border-red-400/40 bg-red-500/10 p-3 text-xs text-red-200">
              {state.message}
            </p>
          )}
        </div>
      </form>
    </Card>
  );
}
