'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import clsx from 'clsx';
import dynamic from 'next/dynamic';
import {
  ArrowLeft,
  Brain,
  Check,
  ChevronDown,
  Copy,
  Crosshair,
  FileCode2,
  FileText,
  Download,
  Link2,
  MessageSquare,
  Microscope,
  SearchX,
  ShieldAlert,
  ThumbsUp,
  Users,
  Wrench,
} from 'lucide-react';
import { useIncidentStream, type SSEEvent } from '@/lib/sse';
import {
  ApiError,
  type ApiRecord,
  apiUrl,
  approveStep,
  escalateStep,
  fetchIncident,
  fetchIncidentEvents,
  fetchIncidentSteps,
  generateDetectionRule,
  generateIncidentHunt,
  rejectStep,
  submitFeedback,
} from '@/lib/api';
import { STATUS_META, VERDICT_META, attackUrl, formatDateTime, humanize } from '@/lib/format';
import AppShell from '@/components/AppShell';
import ErrorNotice, { describeError } from '@/components/ErrorNotice';
import {
  Card,
  CountBadge,
  EmptyState,
  LiveIndicator,
  LoadingBlock,
  SeverityBadge,
  Skeleton,
  Spinner,
  StatusText,
  VerdictBadge,
} from '@/components/ui';

// The report renderer is only needed once CHRON starts writing; keep it out of the first load.
const Markdown = dynamic(() => import('@/components/Markdown'), {
  loading: () => <Skeleton className="h-24 w-full" />,
});

function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return describeError(err);
  return fallback;
}

const PERSONAS: { key: string; label: string; role: string }[] = [
  { key: 'CMDR', label: 'Commander', role: 'Triage & severity' },
  { key: 'ANLST', label: 'Analyst', role: 'Evidence & root cause' },
  { key: 'STRAT', label: 'Strategist', role: 'Containment plan' },
  { key: 'OPS', label: 'Operator', role: 'Executes approved steps' },
  { key: 'CHRON', label: 'Chronicler', role: 'Incident report' },
];

const PERSONA_COLORS: Record<string, string> = {
  CMDR: 'text-warroom-cmdr',
  ANLST: 'text-warroom-anlst',
  STRAT: 'text-warroom-strat',
  OPS: 'text-warroom-ops',
  CHRON: 'text-warroom-chron',
};
const PERSONA_DOTS: Record<string, string> = {
  CMDR: 'bg-warroom-cmdr',
  ANLST: 'bg-warroom-anlst',
  STRAT: 'bg-warroom-strat',
  OPS: 'bg-warroom-ops',
  CHRON: 'bg-warroom-chron',
};

const ATTACK_TACTIC_COLORS: Record<string, string> = {
  'Initial Access': 'bg-red-500/15 border-red-400/40 text-red-300',
  Execution: 'bg-orange-500/15 border-orange-400/40 text-orange-300',
  Persistence: 'bg-yellow-500/15 border-yellow-400/40 text-yellow-300',
  'Privilege Escalation': 'bg-amber-500/15 border-amber-400/40 text-amber-300',
  'Defense Evasion': 'bg-purple-500/15 border-purple-400/40 text-purple-300',
  'Credential Access': 'bg-pink-500/15 border-pink-400/40 text-pink-300',
  Discovery: 'bg-cyan-500/15 border-cyan-400/40 text-cyan-300',
  'Lateral Movement': 'bg-indigo-500/15 border-indigo-400/40 text-indigo-300',
  Collection: 'bg-blue-500/15 border-blue-400/40 text-blue-300',
  'Command and Control': 'bg-fuchsia-500/15 border-fuchsia-400/40 text-fuchsia-300',
  Exfiltration: 'bg-rose-500/15 border-rose-400/40 text-rose-300',
  Impact: 'bg-red-600/15 border-red-400/40 text-red-200',
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-300',
  HIGH: 'text-orange-300',
  MEDIUM: 'text-yellow-300',
  LOW: 'text-emerald-300',
};

interface AttackTechnique {
  technique_id: string;
  name?: string;
  tactic?: string;
  confidence?: number;
}

// Events only carry AWAITING_APPROVAL → APPROVED/REJECTED/ESCALATED; the steps
// endpoint also reports what happened next (EXECUTING, DRY_RUN_OK, BLOCKED…).
type StepStatus = string;
interface ApprovalStep {
  step_id: string;
  step_number: number;
  description: string;
  risk_level: string;
  action_type?: string;
  rollback?: string;
  status: StepStatus;
  /** Set when the two-person rule sent an approved step back for a second, distinct approver. */
  firstApprover?: string;
}

interface HuntQuery { platform: string; query: string; description?: string }
interface HuntHypothesis {
  title: string;
  rationale?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  tactic?: string;
  data_sources?: string[];
  queries?: HuntQuery[];
  expected_findings?: string;
  false_positive_notes?: string;
  priority?: 'HIGH' | 'MEDIUM' | 'LOW';
}
interface HuntPlan { generated_from: string; summary?: string; hypotheses: HuntHypothesis[] }

const STEP_TONE: Record<string, string> = {
  APPROVED: 'border-warroom-success/30 text-warroom-success',
  EXECUTING: 'border-warroom-success/30 text-warroom-success',
  DRY_RUN_OK: 'border-warroom-success/30 text-warroom-success',
  COMPLETED: 'border-warroom-success/30 text-warroom-success',
  ESCALATED: 'border-warroom-warning/30 text-warroom-warning',
  REJECTED: 'border-red-400/30 text-red-300',
  BLOCKED: 'border-red-400/30 text-red-300',
  FAILED: 'border-red-400/30 text-red-300',
  ROLLED_BACK: 'border-red-400/30 text-red-300',
};

function decisionToStatus(decision: unknown): StepStatus {
  if (decision === 'rejected') return 'REJECTED';
  if (decision === 'escalated') return 'ESCALATED';
  return 'APPROVED'; // approved, auto_approved_timeout
}

/** Everything the page shows that comes from the incident's event log. */
function deriveFromEvents(events: SSEEvent[]) {
  const timeline: SSEEvent[] = [];
  const toolResults: Record<string, SSEEvent> = {};
  const steps: Record<string, ApprovalStep> = {};
  const thinking: string[] = [];
  let pir = '';
  let jira: { ticket_id?: string; ticket_url?: string } | null = null;
  for (const e of events) {
    switch (e.type) {
      case 'agent.message':
      case 'tool.called':
        timeline.push(e);
        break;
      case 'tool.result':
        toolResults[`${e.tool}|${e.round}`] = e;
        break;
      case 'approval.required':
        if (e.step_id) {
          const prev = steps[e.step_id];
          steps[e.step_id] = prev
            ? // Re-requested after a first approval (two-person rule): keep the details.
              { ...prev, status: 'AWAITING_APPROVAL', firstApprover: prev.firstApprover ?? 'another approver' }
            : {
                step_id: e.step_id,
                step_number: Number(e.step_number),
                description: e.description,
                risk_level: e.risk_level,
                action_type: e.action_type,
                rollback: e.rollback && e.rollback !== 'None' ? e.rollback : undefined,
                status: 'AWAITING_APPROVAL',
              };
        }
        break;
      case 'approval.received':
        if (e.step_id && steps[e.step_id])
          steps[e.step_id] = {
            ...steps[e.step_id],
            status: decisionToStatus(e.decision),
            firstApprover: typeof e.approver === 'string' ? e.approver : steps[e.step_id].firstApprover,
          };
        break;
      case 'thinking.chunk': {
        const text = e.content ?? e.text;
        if (typeof text === 'string' && text) thinking.push(text);
        break;
      }
      case 'pir.streaming':
        pir += e.content || '';
        break;
      case 'jira.ticket_created':
        jira = { ticket_id: e.ticket_id, ticket_url: e.ticket_url };
        break;
    }
  }
  return { timeline, toolResults, steps, thinking, pir, jira };
}

export default function IncidentPage() {
  const params = useParams();
  const incidentId = params.id as string;
  const [incident, setIncident] = useState<ApiRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  // History comes from two places: the REST event log (works without a live
  // connection) and the SSE stream, which replays the same log on connect and
  // then continues live. Once the stream has delivered anything it is the
  // single source of truth, so the two are never merged (no duplicates).
  const [restEvents, setRestEvents] = useState<SSEEvent[]>([]);
  const [liveEvents, setLiveEvents] = useState<SSEEvent[]>([]);
  const [restSteps, setRestSteps] = useState<ApiRecord[]>([]);

  const [thinkingExpanded, setThinkingExpanded] = useState(true);
  const [hunt, setHunt] = useState<HuntPlan | null>(null);
  const [huntLoading, setHuntLoading] = useState(false);
  const [huntError, setHuntError] = useState('');
  const [detectionRule, setDetectionRule] = useState<{ rule: ApiRecord; yaml: string; path: string } | null>(null);
  const [detectionLoading, setDetectionLoading] = useState(false);
  const [detectionError, setDetectionError] = useState('');
  const chatRef = useRef<HTMLDivElement>(null);

  const loadIncident = useCallback(() => {
    if (!incidentId) return;
    setLoading(true);
    setLoadError(null);
    fetchIncident(incidentId)
      .then(setIncident)
      .catch(setLoadError)
      .finally(() => setLoading(false));
  }, [incidentId]);

  // ----- rehydration on mount -----
  useEffect(() => {
    if (!incidentId) return;
    loadIncident();
    fetchIncidentEvents(incidentId, 500)
      .then(data => setRestEvents(((data.events || []) as SSEEvent[]).slice().reverse())) // oldest-first
      .catch(() => { /* live stream still works; history is best-effort */ });
    // Covers a refresh after the approval event scrolled off the bounded log.
    fetchIncidentSteps(incidentId)
      .then(data => setRestSteps(data.steps || []))
      .catch(() => { /* steps are re-sent over SSE */ });
  }, [incidentId, loadIncident]);

  // ----- live SSE events (every event, so bursts aren't dropped) -----
  const { connected } = useIncidentStream(incidentId, (evt: SSEEvent) => {
    setLiveEvents(prev => [...prev.slice(-999), evt]);
    if (evt.type === 'approval.received' || evt.type.startsWith('step.')) {
      refreshSteps();
    }
    if (evt.type === 'triage.complete' || evt.type === 'investigation.complete' || evt.type === 'incident.resolved') {
      fetchIncident(incidentId).then(setIncident).catch(() => {});
    }
  });

  const events = liveEvents.length > 0 ? liveEvents : restEvents;
  const derived = useMemo(() => deriveFromEvents(events), [events]);

  const approvalSteps = useMemo(() => {
    const merged: Record<string, ApprovalStep> = { ...derived.steps };
    for (const s of restSteps) {
      // PENDING steps are low-risk ones that run without approval; skip them.
      if (!s.status || s.status === 'PENDING') continue;
      const fromEvents = merged[s.id];
      // The stored status is authoritative once it has moved past the event's
      // view, and when a stored first approval means a second one is pending.
      if (!fromEvents || s.status !== 'AWAITING_APPROVAL' || s.approved_by) {
        merged[s.id] = {
          step_id: s.id,
          step_number: Number(s.step_number),
          description: s.description,
          risk_level: s.risk_level,
          action_type: s.action_type,
          rollback: s.rollback_procedure || fromEvents?.rollback,
          status: s.status,
          firstApprover: s.status === 'AWAITING_APPROVAL' && s.approved_by ? s.approved_by : undefined,
        };
      }
    }
    return Object.values(merged).sort((a, b) => a.step_number - b.step_number);
  }, [derived.steps, restSteps]);

  const refreshSteps = useCallback(() => {
    fetchIncidentSteps(incidentId)
      .then(data => setRestSteps(data.steps || []))
      .catch(() => {});
  }, [incidentId]);

  const pendingSteps = approvalSteps.filter(s => s.status === 'AWAITING_APPROVAL');

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [derived.timeline.length]);

  const attackTechniques: AttackTechnique[] = useMemo(() => incident?.triage_result?.attack_techniques ?? [], [incident]);
  const verdict: string | undefined = incident?.triage_result?.verdict;
  const finding: ApiRecord | null = incident?.investigation_finding ?? null;

  const runHunt = async () => {
    setHuntLoading(true);
    setHuntError('');
    try {
      setHunt((await generateIncidentHunt(incidentId)) as HuntPlan);
    } catch (err) {
      setHuntError(errorMessage(err, 'Threat-hunt generation failed. Try again.'));
    } finally {
      setHuntLoading(false);
    }
  };

  const runDetectionRule = async () => {
    setDetectionLoading(true);
    setDetectionError('');
    try {
      setDetectionRule(await generateDetectionRule(incidentId));
    } catch (err) {
      setDetectionError(errorMessage(err, 'Detection-rule generation failed. Try again.'));
    } finally {
      setDetectionLoading(false);
    }
  };

  const notFound = loadError instanceof ApiError && loadError.status === 404;

  if (notFound) {
    return (
      <AppShell>
        <EmptyState
          icon={<SearchX className="h-5 w-5" />}
          title="Incident not found"
          className="mx-auto mt-10 max-w-lg"
          action={
            <Link href="/dashboard" className="btn btn-primary btn-sm">
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              Back to incident feed
            </Link>
          }
        >
          No incident has the ID <code className="break-all font-mono text-xs text-fg">{incidentId}</code>. It may have
          been purged, or the link is incomplete.
        </EmptyState>
      </AppShell>
    );
  }

  return (
    <AppShell status={<LiveIndicator connected={connected} compact />}>
      {/* ---------- incident header ---------- */}
      <div className="mb-6">
        <Link href="/dashboard" className="mb-3 inline-flex items-center gap-1 text-sm text-fg-muted hover:text-fg">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Incident feed
        </Link>
        {loading && !incident ? (
          <LoadingBlock label="Loading incident">
            <Skeleton className="mb-3 h-6 w-64" />
            <Skeleton className="h-4 w-full max-w-2xl" />
          </LoadingBlock>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={incident?.severity} />
              <VerdictBadge verdict={verdict} />
              <StatusText status={incident?.status} />
              {incident && incident.alert_count > 1 && (
                <CountBadge count={incident.alert_count} title="Correlated alerts folded into this incident" />
              )}
            </div>
            <h1 className="mt-2 flex flex-wrap items-baseline gap-x-3 text-xl font-semibold sm:text-2xl">
              {incident?.affected_service ?? 'Incident'}
              <span className="font-mono text-sm font-normal text-fg-subtle">#{incidentId.slice(0, 8)}</span>
            </h1>
            {incident?.alert_message && (
              <p className="mt-2 max-w-3xl break-words text-sm text-fg-muted">{incident.alert_message}</p>
            )}
          </>
        )}
      </div>

      <ErrorNotice error={notFound ? null : loadError} onRetry={loadIncident} className="mb-6" />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* ---------- main column ---------- */}
        <div className="min-w-0 space-y-6 lg:col-span-2">
          {/* Approvals first: they are the only thing waiting on a human. */}
          {approvalSteps.length > 0 && (
            <section aria-labelledby="approvals-heading" className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 id="approvals-heading" className="flex items-center gap-2 text-sm font-semibold">
                  <ShieldAlert className="h-4 w-4 text-warroom-warning" aria-hidden="true" />
                  Containment plan
                </h2>
                <span className="text-xs text-fg-subtle">
                  {pendingSteps.length > 0
                    ? `${pendingSteps.length} step${pendingSteps.length === 1 ? '' : 's'} need${pendingSteps.length === 1 ? 's' : ''} approval`
                    : 'All steps decided'}
                </span>
              </div>
              {approvalSteps.map(step => (
                <ApprovalCard key={step.step_id} step={step} onDecided={refreshSteps} />
              ))}
            </section>
          )}

          {attackTechniques.length > 0 && (
            <Card title="MITRE ATT&CK mapping" icon={<Crosshair className="h-4 w-4" />} titleId="attack-heading" action={<span className="text-2xs text-fg-subtle">Triaged by CMDR</span>}>
              <ul className="flex flex-wrap gap-2">
                {attackTechniques.map((t, i) => (
                  <li key={i}>
                    <a
                      href={attackUrl(t.technique_id)}
                      target="_blank"
                      rel="noreferrer"
                      className={clsx(
                        'inline-flex min-h-[2rem] items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs transition-opacity hover:opacity-80',
                        ATTACK_TACTIC_COLORS[t.tactic || ''] || 'border-line-strong bg-surface-raised text-fg-muted',
                      )}
                      title={t.tactic ? `Tactic: ${t.tactic}` : undefined}
                    >
                      <span className="font-mono font-semibold">{t.technique_id}</span>
                      {t.name && <span>{t.name}</span>}
                      {typeof t.confidence === 'number' && <span className="opacity-75">{Math.round(t.confidence * 100)}%</span>}
                      <span className="sr-only">(opens MITRE ATT&amp;CK in a new tab)</span>
                    </a>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <ThinkingPanel chunks={derived.thinking} expanded={thinkingExpanded} onToggle={() => setThinkingExpanded(v => !v)} />

          <Card
            title="War room timeline"
            icon={<MessageSquare className="h-4 w-4" />}
            titleId="timeline-heading"
            action={<span className="text-2xs text-fg-subtle">{derived.timeline.length} entries</span>}
            bodyClassName="p-0 sm:p-0"
          >
            <div
              ref={chatRef}
              className="max-h-[32rem] space-y-1 overflow-y-auto p-4 sm:p-5"
              aria-live="polite"
              aria-relevant="additions"
              tabIndex={0}
              aria-label="Agent messages and tool calls"
            >
              {derived.timeline.length === 0 ? (
                <div className="py-8 text-center text-sm text-fg-subtle">
                  {connected ? (
                    <Spinner label="Waiting for the agents to report…" className="justify-center" />
                  ) : (
                    'No agent activity recorded yet.'
                  )}
                </div>
              ) : (
                derived.timeline.map((e, i) =>
                  e.type === 'tool.called' ? (
                    <ToolCallEntry key={i} event={e} result={derived.toolResults[`${e.tool}|${e.round}`]} />
                  ) : (
                    <AgentMessage key={i} event={e} />
                  ),
                )
              )}
            </div>
          </Card>

          {finding && <InvestigationCard finding={finding} />}

          {derived.pir && <PIRStream content={derived.pir} jiraTicket={derived.jira} />}
        </div>

        {/* ---------- sidebar ---------- */}
        <aside className="min-w-0 space-y-6" aria-label="Incident details and tools">
          {incident && (
            <Card title="Details" icon={<FileText className="h-4 w-4" />} titleId="details-heading">
              <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-sm">
                <dt className="text-fg-subtle">Status</dt>
                <dd>{STATUS_META[incident.status]?.label ?? humanize(incident.status)}</dd>
                <dt className="text-fg-subtle">Service</dt>
                <dd className="break-words">{incident.affected_service}</dd>
                <dt className="text-fg-subtle">Source</dt>
                <dd>{humanize(incident.source)}</dd>
                <dt className="text-fg-subtle">Category</dt>
                <dd>{humanize(incident.category)}</dd>
                {verdict && (
                  <>
                    <dt className="text-fg-subtle">Verdict</dt>
                    <dd>{VERDICT_META[verdict]?.label ?? humanize(verdict)}</dd>
                  </>
                )}
                {incident.triage_result?.blast_radius && (
                  <>
                    <dt className="text-fg-subtle">Blast radius</dt>
                    <dd>{humanize(incident.triage_result.blast_radius)}</dd>
                  </>
                )}
                <dt className="text-fg-subtle">Opened</dt>
                <dd>
                  <time dateTime={incident.created_at}>{formatDateTime(incident.created_at)}</time>
                </dd>
                {incident.resolved_at && (
                  <>
                    <dt className="text-fg-subtle">Resolved</dt>
                    <dd>
                      <time dateTime={incident.resolved_at}>{formatDateTime(incident.resolved_at)}</time>
                    </dd>
                  </>
                )}
              </dl>
            </Card>
          )}

          <AgentStatusPanel events={events} />

          {incident && incident.alert_count > 1 && (
            <Card title={`Correlated alerts · ×${incident.alert_count}`} icon={<Link2 className="h-4 w-4" />} titleId="corr-heading">
              <p className="mb-3 text-xs text-fg-muted">
                {incident.alert_count} raw alerts were folded into this one incident instead of {incident.alert_count} separate
                investigations.
              </p>
              <ul className="max-h-48 space-y-2 overflow-y-auto">
                {(Array.isArray(incident.related_signals) ? incident.related_signals : [])
                  .slice(-6)
                  .reverse()
                  .map((s: ApiRecord, i: number) => (
                    <li key={i} className="border-l-2 border-warroom-anlst/40 pl-2 text-xs">
                      <span className="font-mono text-warroom-anlst">{s.reason}</span>
                      <span className="text-fg-subtle"> · {s.source}</span>
                      <div className="truncate text-fg-muted">{s.alert_message}</div>
                    </li>
                  ))}
              </ul>
            </Card>
          )}

          <HuntPanel hunt={hunt} loading={huntLoading} error={huntError} onGenerate={runHunt} />
          <DetectionRulePanel rule={detectionRule} loading={detectionLoading} error={detectionError} onGenerate={runDetectionRule} />
          <FeedbackPanel incidentId={incidentId} />

          <Card title="Export & tickets" icon={<Download className="h-4 w-4" />} titleId="export-heading">
            <a href={apiUrl(`/api/v1/incidents/${incidentId}/export/stix`)} className="btn btn-secondary btn-sm w-full" download>
              <Download className="h-4 w-4" aria-hidden="true" />
              Export STIX 2.1 bundle
            </a>
            {derived.jira?.ticket_id && (
              <p className="mt-3 text-xs text-fg-muted">
                JIRA ticket{' '}
                <a
                  href={derived.jira.ticket_url || '#'}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-warroom-chron underline-offset-2 hover:underline"
                >
                  {derived.jira.ticket_id}
                </a>{' '}
                created via the SentinelForge MCP server.
              </p>
            )}
          </Card>
        </aside>
      </div>
    </AppShell>
  );
}

function ThinkingPanel({ chunks, expanded, onToggle }: { chunks: string[]; expanded: boolean; onToggle: () => void }) {
  if (chunks.length === 0) return null;
  return (
    <section className="thinking-panel p-4 sm:p-5" aria-label="Live reasoning trace">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls="thinking-body"
        className="flex w-full items-center gap-2 rounded-lg text-left"
      >
        <Brain className="h-4 w-4 text-warroom-thinking" aria-hidden="true" />
        <span className="text-sm font-semibold text-warroom-chron">Live reasoning trace</span>
        <span className="hidden rounded-md bg-warroom-thinking/20 px-2 py-0.5 text-2xs text-warroom-chron sm:inline">
          open model · reasoning
        </span>
        <ChevronDown
          className={clsx('ml-auto h-4 w-4 text-fg-subtle transition-transform', expanded && 'rotate-180')}
          aria-hidden="true"
        />
      </button>
      {expanded && (
        <div id="thinking-body" className="mt-3 max-h-48 overflow-y-auto whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">
          <span className="typing-cursor">{chunks.join('')}</span>
        </div>
      )}
    </section>
  );
}

function InvestigationCard({ finding }: { finding: ApiRecord }) {
  const iocs: ApiRecord[] = Array.isArray(finding.iocs) ? finding.iocs : [];
  const evidence: ApiRecord[] = Array.isArray(finding.evidence) ? finding.evidence : [];
  const confidence = typeof finding.confidence_score === 'number' ? Math.round(finding.confidence_score * 100) : null;
  return (
    <Card
      title="Investigation finding"
      icon={<Microscope className="h-4 w-4" />}
      titleId="finding-heading"
      action={confidence !== null ? <span className="text-xs text-fg-muted">Confidence {confidence}%</span> : undefined}
    >
      {finding.root_cause && <p className="text-sm text-fg">{finding.root_cause}</p>}
      {finding.blast_radius_assessment && <p className="mt-2 text-xs text-fg-muted">{finding.blast_radius_assessment}</p>}
      {iocs.length > 0 && (
        <div className="mt-4">
          <h3 className="eyebrow mb-2">Indicators</h3>
          <ul className="flex flex-wrap gap-2">
            {iocs.map((ioc, i) => (
              <li key={i} className="badge border-line-strong bg-canvas font-mono text-fg-muted">
                <span className="text-fg-subtle">{ioc.type}:</span> {ioc.value}
                {ioc.verdict && ioc.verdict !== 'UNKNOWN' && <span className="text-red-300">· {humanize(ioc.verdict)}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {evidence.length > 0 && (
        <div className="mt-4">
          <h3 className="eyebrow mb-2">Evidence</h3>
          <ul className="space-y-1.5 text-xs">
            {evidence.map((ev, i) => (
              <li key={i} className="flex gap-2">
                <span className="shrink-0 font-mono text-warroom-anlst">{ev.source}</span>
                <span className="min-w-0 break-words text-fg-muted">{ev.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

const HUNT_PRIORITY_COLORS: Record<string, string> = {
  HIGH: 'border-red-400/40 bg-red-500/15 text-red-300',
  MEDIUM: 'border-yellow-400/40 bg-yellow-500/10 text-yellow-300',
  LOW: 'border-line-strong bg-surface-raised text-fg-muted',
};

function HuntPanel({
  hunt,
  loading,
  error,
  onGenerate,
}: {
  hunt: HuntPlan | null;
  loading: boolean;
  error: string;
  onGenerate: () => void;
}) {
  return (
    <Card
      title="Threat hunt"
      icon={<Crosshair className="h-4 w-4" />}
      titleId="hunt-heading"
      action={
        <button type="button" onClick={onGenerate} disabled={loading} className="btn btn-accent btn-sm">
          {loading ? <Spinner label="Hunting…" /> : hunt ? 'Regenerate' : 'Generate'}
        </button>
      }
    >
      {!hunt && !loading && !error && (
        <p className="text-xs text-fg-muted">
          Turn this incident&apos;s ATT&amp;CK techniques into proactive hunt hypotheses with runnable queries.
        </p>
      )}
      {error && <p role="alert" className="field-error mt-0">{error}</p>}
      {hunt && (
        <div className="max-h-[26rem] space-y-3 overflow-y-auto">
          {hunt.summary && <p className="text-xs text-fg-muted">{hunt.summary}</p>}
          {hunt.hypotheses.length === 0 && <p className="text-xs text-fg-subtle">No hypotheses generated for this incident.</p>}
          {hunt.hypotheses.map((h, i) => (
            <div key={i} className="rounded-lg border border-line p-3">
              <div className="flex items-start gap-2">
                <span className={clsx('badge shrink-0', HUNT_PRIORITY_COLORS[h.priority || 'MEDIUM'])}>{h.priority || 'MEDIUM'}</span>
                <span className="text-xs font-semibold text-fg">{h.title}</span>
              </div>
              {h.mitre_technique_id && (
                <div className="mt-1 font-mono text-2xs text-fg-subtle">
                  {h.mitre_technique_id} {h.mitre_technique_name} · {h.tactic}
                </div>
              )}
              {h.rationale && <p className="mt-1 text-xs text-fg-muted">{h.rationale}</p>}
              {(h.queries || []).map((q, j) => (
                <div key={j} className="mt-2">
                  <div className="text-2xs font-semibold uppercase text-warroom-anlst">{q.platform}</div>
                  <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded-md bg-canvas p-2 text-2xs text-fg-muted">{q.query}</pre>
                </div>
              ))}
              {h.expected_findings && (
                <p className="mt-2 text-2xs text-fg-subtle">
                  <span className="text-fg-muted">Expect:</span> {h.expected_findings}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

const FEEDBACK_OPTIONS: { verdict: string; label: string; className: string }[] = [
  { verdict: 'TRUE_POSITIVE', label: 'True positive', className: 'btn-danger' },
  { verdict: 'FALSE_POSITIVE', label: 'False positive', className: 'btn-success' },
  { verdict: 'BENIGN_ANOMALY', label: 'Benign', className: 'btn-warning' },
  { verdict: 'NEEDS_HUMAN', label: 'Needs human', className: 'btn-secondary' },
];

function FeedbackPanel({ incidentId }: { incidentId: string }) {
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState('');

  const handleFeedback = async (verdict: string) => {
    setError('');
    setBusy(verdict);
    try {
      await submitFeedback(incidentId, verdict);
      setSubmitted(verdict);
    } catch (err) {
      setError(errorMessage(err, 'Could not record feedback. Try again.'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card title="Was this triage right?" icon={<ThumbsUp className="h-4 w-4" />} titleId="feedback-heading">
      {submitted ? (
        <p role="status" className="flex items-center gap-2 text-sm text-warroom-success">
          <Check className="h-4 w-4" aria-hidden="true" />
          Recorded as {VERDICT_META[submitted]?.label.toLowerCase() ?? humanize(submitted)}. Thanks — this tunes future triage.
        </p>
      ) : (
        <>
          <p className="mb-3 text-xs text-fg-muted">Your verdict is stored with the incident and feeds the triage evaluation set.</p>
          <div className="grid grid-cols-2 gap-2">
            {FEEDBACK_OPTIONS.map(o => (
              <button
                key={o.verdict}
                type="button"
                onClick={() => handleFeedback(o.verdict)}
                disabled={busy !== null}
                className={clsx('btn btn-sm', o.className)}
              >
                {busy === o.verdict ? <Spinner /> : o.label}
              </button>
            ))}
          </div>
        </>
      )}
      {error && <p role="alert" className="field-error">{error}</p>}
    </Card>
  );
}

function DetectionRulePanel({
  rule,
  loading,
  error,
  onGenerate,
}: {
  rule: { rule: ApiRecord; yaml: string; path: string } | null;
  loading: boolean;
  error: string;
  onGenerate: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    if (!rule?.yaml) return;
    navigator.clipboard
      ?.writeText(rule.yaml)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {});
  };
  return (
    <Card
      title="Sigma detection rule"
      icon={<FileCode2 className="h-4 w-4" />}
      titleId="sigma-heading"
      action={
        <button type="button" onClick={onGenerate} disabled={loading} className="btn btn-warning btn-sm">
          {loading ? <Spinner label="Generating…" /> : rule ? 'Regenerate' : 'Generate'}
        </button>
      }
    >
      {!rule && !loading && !error && (
        <p className="text-xs text-fg-muted">Generate a Sigma rule from this incident&apos;s IOCs and MITRE techniques.</p>
      )}
      {error && <p role="alert" className="field-error mt-0">{error}</p>}
      {rule && (
        <div>
          {rule.rule?.title && <p className="mb-2 text-xs font-semibold text-fg">{rule.rule.title}</p>}
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-canvas p-2 text-2xs text-fg-muted">{rule.yaml}</pre>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <span className="break-all font-mono text-2xs text-fg-subtle">{rule.path}</span>
            <button type="button" onClick={copy} className="btn btn-secondary btn-sm">
              {copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
              {copied ? 'Copied' : 'Copy YAML'}
            </button>
          </div>
        </div>
      )}
    </Card>
  );
}

function AgentMessage({ event }: { event: SSEEvent }) {
  const persona = event.persona || 'AGENT';
  const color = PERSONA_COLORS[persona] || 'text-fg-muted';
  const dot = PERSONA_DOTS[persona] || 'bg-slate-400';
  return (
    <div className="agent-message flex gap-3 rounded-lg px-2 py-2 hover:bg-surface-raised/60">
      <span className={clsx('mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full', dot)} aria-hidden="true" />
      <p className="min-w-0 flex-1 break-words text-sm leading-relaxed text-fg">
        <span className={clsx('mr-2 font-mono text-xs font-bold', color)}>{persona}</span>
        {event.text}
      </p>
    </div>
  );
}

function ToolCallEntry({ event, result }: { event: SSEEvent; result?: SSEEvent }) {
  const [expanded, setExpanded] = useState(false);
  const resultPayload = result?.payload || result?.result;
  const preview = useMemo(() => {
    if (resultPayload === undefined) return undefined;
    if (typeof resultPayload === 'string') return resultPayload.slice(0, 1200);
    try {
      return JSON.stringify(resultPayload, null, 2).slice(0, 1200);
    } catch {
      return String(resultPayload).slice(0, 1200);
    }
  }, [resultPayload]);
  const args = useMemo(() => {
    if (!event.args) return '';
    if (typeof event.args === 'string') return event.args.slice(0, 120);
    try {
      return JSON.stringify(event.args).slice(0, 120);
    } catch {
      return '';
    }
  }, [event.args]);

  return (
    <div className="tool-entry my-1 ml-5 py-2 pl-3 pr-2">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Wrench className="h-3.5 w-3.5 text-warroom-anlst" aria-hidden="true" />
        <span className="font-mono text-xs font-semibold text-fg">{event.tool || 'tool'}</span>
        {result ? (
          <span className="inline-flex items-center gap-1 text-2xs text-warroom-success">
            <Check className="h-3 w-3" aria-hidden="true" />
            done
          </span>
        ) : (
          <Spinner className="text-2xs text-warroom-warning" label="running" />
        )}
        {args && <span className="min-w-0 max-w-full truncate font-mono text-2xs text-fg-subtle">{args}</span>}
        {result && preview && (
          <button
            type="button"
            onClick={() => setExpanded(v => !v)}
            aria-expanded={expanded}
            className="btn btn-ghost btn-sm ml-auto min-h-[1.75rem] px-2 py-0.5"
          >
            {expanded ? 'Hide result' : 'Show result'}
          </button>
        )}
      </div>
      {expanded && preview && (
        <pre className="mt-2 max-h-48 overflow-auto rounded-md bg-canvas p-2 text-2xs text-fg-muted">{preview}</pre>
      )}
    </div>
  );
}

function ApprovalCard({ step, onDecided }: { step: ApprovalStep; onDecided: () => void }) {
  const [ratOpen, setRatOpen] = useState(false);
  const [rationale, setRationale] = useState('');
  const [busy, setBusy] = useState<null | 'approved' | 'rejected' | 'escalated'>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const rationaleId = `rationale-${step.step_id}`;

  const handle = async (action: 'approved' | 'rejected' | 'escalated') => {
    if (!step.step_id || busy) return;
    setBusy(action);
    setError('');
    setNotice('');
    try {
      let res: { status: string };
      if (action === 'approved') res = await approveStep(step.step_id, rationale);
      else if (action === 'rejected') res = await rejectStep(step.step_id, rationale || 'Rejected by operator');
      else res = await escalateStep(step.step_id, rationale || 'Escalated by operator');
      // The card flips state when the approval.received event arrives over SSE;
      // until then (or when a second approver is still needed) say what happened.
      setNotice(`Decision recorded (${humanize(res?.status)}).`);
      onDecided();
    } catch (err) {
      setError(errorMessage(err, 'Decision was not recorded. Try again.'));
    } finally {
      setBusy(null);
    }
  };

  if (step.status !== 'AWAITING_APPROVAL') {
    const tone = STEP_TONE[step.status] ?? 'border-line-strong text-fg-muted';
    return (
      <div className={clsx('card flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-sm', tone)}>
        <Check className="h-4 w-4" aria-hidden="true" />
        <span className="font-semibold">Step {step.step_number}</span>
        <span className="min-w-0 flex-1 truncate text-fg-muted">{step.description}</span>
        <span className="text-xs font-semibold">{humanize(step.status)}</span>
      </div>
    );
  }

  return (
    <article className="approval-card p-4 sm:p-5" aria-labelledby={`step-${step.step_id}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="badge border-warroom-warning/50 bg-warroom-warning/15 text-warroom-warning">
          {step.firstApprover ? 'Second approver needed' : 'Approval required'}
        </span>
        <span className="text-xs text-fg-muted">Step {step.step_number}</span>
        {step.action_type && <span className="font-mono text-2xs text-fg-subtle">{step.action_type}</span>}
      </div>
      <h3 id={`step-${step.step_id}`} className="mt-2 text-base font-semibold text-fg">
        {step.description}
      </h3>
      <dl className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs">
        <div className="flex gap-1">
          <dt className="text-fg-subtle">Risk</dt>
          <dd className={clsx('font-semibold', RISK_COLORS[step.risk_level] ?? 'text-warroom-warning')}>{step.risk_level}</dd>
        </div>
        <div className="flex gap-1">
          <dt className="text-fg-subtle">Rollback</dt>
          <dd className="text-fg-muted">{step.rollback ? 'Available' : 'None'}</dd>
        </div>
      </dl>
      {step.rollback && <p className="mt-1 text-xs text-fg-subtle">{step.rollback}</p>}
      {step.firstApprover && (
        <p className="mt-2 text-xs text-warroom-warning">
          Two-person rule: approved by {step.firstApprover}. A different operator with the approver role must approve it too.
        </p>
      )}

      <div className="mt-3">
        <button
          type="button"
          onClick={() => setRatOpen(v => !v)}
          aria-expanded={ratOpen}
          aria-controls={rationaleId}
          className="text-xs text-fg-muted underline underline-offset-2 hover:text-fg"
        >
          {ratOpen ? 'Hide rationale' : 'Add rationale (optional)'}
        </button>
        {ratOpen && (
          <div className="mt-2">
            <label htmlFor={rationaleId} className="sr-only">
              Rationale for step {step.step_number}
            </label>
            <textarea
              id={rationaleId}
              value={rationale}
              onChange={e => setRationale(e.target.value)}
              placeholder="Why you're approving, rejecting or escalating. Stored in the tamper-evident audit log."
              rows={2}
              className="input resize-y"
            />
          </div>
        )}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
        <button type="button" disabled={busy !== null} onClick={() => handle('approved')} className="btn btn-success">
          {busy === 'approved' ? <Spinner label="Approving…" /> : 'Approve'}
        </button>
        <button type="button" disabled={busy !== null} onClick={() => handle('rejected')} className="btn btn-danger">
          {busy === 'rejected' ? <Spinner label="Rejecting…" /> : 'Reject'}
        </button>
        <button type="button" disabled={busy !== null} onClick={() => handle('escalated')} className="btn btn-warning">
          {busy === 'escalated' ? <Spinner label="Escalating…" /> : 'Escalate'}
        </button>
      </div>
      <div aria-live="polite">
        {notice && <p className="mt-3 text-xs text-emerald-200">{notice}</p>}
      </div>
      {error && <p role="alert" className="field-error">{error}</p>}
    </article>
  );
}

function PIRStream({ content, jiraTicket }: { content: string; jiraTicket?: { ticket_id?: string; ticket_url?: string } | null }) {
  return (
    <Card
      title="Security incident report"
      icon={<FileText className="h-4 w-4" />}
      titleId="pir-heading"
      action={<span className="font-mono text-2xs text-warroom-chron">CHRON</span>}
      className="border-warroom-chron/30"
    >
      <div className="markdown max-h-96 overflow-y-auto">
        <Markdown content={content} />
      </div>
      {jiraTicket?.ticket_id && (
        <p className="mt-3 border-t border-line pt-3 text-xs text-fg-muted">
          Filed as{' '}
          <a href={jiraTicket.ticket_url || '#'} target="_blank" rel="noreferrer" className="font-mono text-warroom-chron hover:underline">
            {jiraTicket.ticket_id}
          </a>{' '}
          via the SentinelForge MCP server.
        </p>
      )}
    </Card>
  );
}

function AgentStatusPanel({ events }: { events: SSEEvent[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const e of events) if (e.persona) c[e.persona] = (c[e.persona] || 0) + 1;
    return c;
  }, [events]);

  return (
    <Card title="Agent team" icon={<Users className="h-4 w-4" />} titleId="agents-heading">
      <ul className="space-y-2.5">
        {PERSONAS.map(p => {
          const n = counts[p.key] || 0;
          return (
            <li key={p.key} className="flex items-center gap-3 text-sm">
              <span className={clsx('h-2.5 w-2.5 shrink-0 rounded-full', PERSONA_DOTS[p.key], !n && 'opacity-40')} aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className={clsx('font-mono text-xs font-bold', PERSONA_COLORS[p.key])}>{p.key}</span>{' '}
                <span className="text-fg">{p.label}</span>
                <span className="block text-2xs text-fg-subtle">{p.role}</span>
              </span>
              <span className={clsx('text-2xs', n ? 'text-warroom-success' : 'text-fg-subtle')}>
                {n ? `${n} update${n === 1 ? '' : 's'}` : 'Standby'}
              </span>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
