'use client';

import { useEffect, useState, useRef, useMemo } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useIncidentStream, SSEEvent } from '@/lib/sse';
import {
  ApiError,
  type ApiRecord,
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

function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return 'Sign in required';
    if (err.status === 403) return 'Your role is not allowed to do this';
    return err.message;
  }
  return fallback;
}
import ReactMarkdown from 'react-markdown';

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

const VERDICT_COLORS: Record<string, string> = {
  TRUE_POSITIVE: 'bg-red-600',
  FALSE_POSITIVE: 'bg-green-600',
  BENIGN_ANOMALY: 'bg-yellow-600',
  NEEDS_HUMAN: 'bg-orange-500',
};
const VERDICT_LABEL: Record<string, string> = {
  TRUE_POSITIVE: 'TRUE POSITIVE',
  FALSE_POSITIVE: 'FALSE POSITIVE',
  BENIGN_ANOMALY: 'BENIGN ANOMALY',
  NEEDS_HUMAN: 'NEEDS HUMAN',
};

const ATTACK_TACTIC_COLORS: Record<string, string> = {
  'Initial Access': 'bg-red-500/20 border-red-500/40 text-red-300',
  Execution: 'bg-orange-500/20 border-orange-500/40 text-orange-300',
  Persistence: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300',
  'Privilege Escalation': 'bg-amber-500/20 border-amber-500/40 text-amber-300',
  'Defense Evasion': 'bg-purple-500/20 border-purple-500/40 text-purple-300',
  'Credential Access': 'bg-pink-500/20 border-pink-500/40 text-pink-300',
  Discovery: 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300',
  'Lateral Movement': 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300',
  Collection: 'bg-blue-500/20 border-blue-500/40 text-blue-300',
  'Command and Control': 'bg-fuchsia-500/20 border-fuchsia-500/40 text-fuchsia-300',
  Exfiltration: 'bg-rose-500/20 border-rose-500/40 text-rose-300',
  Impact: 'bg-red-700/20 border-red-700/40 text-red-200',
};

interface AttackTechnique {
  technique_id: string;
  name?: string;
  tactic?: string;
  confidence?: number;
}

interface ApprovalStep {
  step_id: string;
  step_number: number;
  description: string;
  risk_level: string;
  action_type?: string;
  rollback?: string;
  status: 'AWAITING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'ESCALATED';
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

export default function IncidentPage() {
  const params = useParams();
  const incidentId = params.id as string;
  const [incident, setIncident] = useState<ApiRecord | null>(null);
  const [agentMessages, setAgentMessages] = useState<SSEEvent[]>([]);
  const [toolCalls, setToolCalls] = useState<SSEEvent[]>([]);
  const [toolResults, setToolResults] = useState<Record<string, SSEEvent>>({}); // keyed by `${tool}|${round}`
  const [approvalSteps, setApprovalSteps] = useState<Record<string, ApprovalStep>>({});
  const [pirContent, setPirContent] = useState('');
  const [jiraTicket, setJiraTicket] = useState<{ ticket_id?: string; ticket_url?: string } | null>(null);
  const [thinkingExpanded, setThinkingExpanded] = useState(true);
  const [hunt, setHunt] = useState<HuntPlan | null>(null);
  const [huntLoading, setHuntLoading] = useState(false);
  const [detectionRule, setDetectionRule] = useState<{ rule: ApiRecord; yaml: string; path: string } | null>(null);
  const [detectionLoading, setDetectionLoading] = useState(false);
  const [actionError, setActionError] = useState('');
  const [loadError, setLoadError] = useState('');
  const chatRef = useRef<HTMLDivElement>(null);

  const runHunt = async () => {
    setHuntLoading(true);
    setActionError('');
    try {
      setHunt((await generateIncidentHunt(incidentId)) as HuntPlan);
    } catch (err) {
      setActionError(errorMessage(err, 'Threat-hunt generation failed'));
    } finally {
      setHuntLoading(false);
    }
  };

  const runDetectionRule = async () => {
    setDetectionLoading(true);
    setActionError('');
    try {
      setDetectionRule(await generateDetectionRule(incidentId));
    } catch (err) {
      setActionError(errorMessage(err, 'Detection-rule generation failed'));
    } finally {
      setDetectionLoading(false);
    }
  };

  const copyYaml = () => {
    if (detectionRule?.yaml) {
      navigator.clipboard?.writeText(detectionRule.yaml).catch(() => {});
    }
  };

  // ----- rehydration on mount -----
  useEffect(() => {
    if (!incidentId) return;
    fetchIncident(incidentId)
      .then(setIncident)
      .catch(err => setLoadError(errorMessage(err, 'Could not load incident')));
    fetchIncidentEvents(incidentId, 500).then(data => {
      const evs = ((data.events || []) as SSEEvent[]).slice().reverse(); // restore oldest-first
      const stepsFromEvs: Record<string, ApprovalStep> = {};
      let pir = '';
      for (const e of evs) {
        if (e.type === 'agent.message') setAgentMessages(prev => [...prev, e]);
        if (e.type === 'tool.called') setToolCalls(prev => [...prev, e]);
        if (e.type === 'tool.result') {
          setToolResults(prev => ({ ...prev, [`${e.tool}|${e.round}`]: e }));
        }
        if (e.type === 'approval.required' && e.step_id) {
          stepsFromEvs[e.step_id] = {
            step_id: e.step_id, step_number: e.step_number, description: e.description,
            risk_level: e.risk_level, action_type: e.action_type, rollback: e.rollback,
            status: 'AWAITING_APPROVAL',
          };
        }
        if (e.type === 'approval.received' && e.step_id) {
          if (stepsFromEvs[e.step_id]) {
            const decision = e.decision === 'approved' ? 'APPROVED'
              : e.decision === 'rejected' ? 'REJECTED'
              : e.decision === 'escalated' ? 'ESCALATED'
              : 'APPROVED';
            stepsFromEvs[e.step_id].status = decision as ApprovalStep['status'];
          }
        }
        if (e.type === 'pir.streaming' && e.content) pir += e.content;
        if (e.type === 'jira.ticket_created') setJiraTicket({ ticket_id: e.ticket_id, ticket_url: e.ticket_url });
      }
      if (Object.keys(stepsFromEvs).length) {
        setApprovalSteps(prev => ({ ...prev, ...stepsFromEvs }));
      }
      if (pir) setPirContent(pir);
    }).catch(() => { /* live stream still works; history is best-effort */ });
    // rehydrate approval cards from the steps REST endpoint (covers a refresh
    // when the approval card event has already scrolled off the bounded event log)
    fetchIncidentSteps(incidentId).then(data => {
      const steps: ApiRecord[] = data.steps || [];
      if (!steps.length) return;
      setApprovalSteps(prev => {
        const next = { ...prev };
        for (const s of steps) {
          if (s.status === 'AWAITING_APPROVAL' || s.status === 'APPROVED' || s.status === 'REJECTED' || s.status === 'ESCALATED') {
            next[s.id] = {
              step_id: s.id, step_number: s.step_number, description: s.description,
              risk_level: s.risk_level, action_type: s.action_type, rollback: s.rollback_procedure,
              status: s.status as ApprovalStep['status'],
            };
          }
        }
        return next;
      });
    }).catch(() => { /* steps are re-sent over SSE */ });
  }, [incidentId]);

  // ----- live SSE events (every event, so bursts aren't dropped) -----
  const [liveEvents, setLiveEvents] = useState<SSEEvent[]>([]);
  const { thinkingChunks, connected } = useIncidentStream(incidentId, (last: SSEEvent) => {
    setLiveEvents(prev => [...prev.slice(-499), last]);

    if (last.type === 'agent.message') setAgentMessages(prev => [...prev, last]);
    if (last.type === 'tool.called') setToolCalls(prev => [...prev, last]);
    if (last.type === 'tool.result') {
      setToolResults(prev => ({ ...prev, [`${last.tool}|${last.round}`]: last }));
    }
    if (last.type === 'approval.required' && last.step_id) {
      setApprovalSteps(prev => ({
        ...prev,
        [last.step_id]: {
          step_id: last.step_id, step_number: last.step_number, description: last.description,
          risk_level: last.risk_level, action_type: last.action_type, rollback: last.rollback,
          status: 'AWAITING_APPROVAL',
        },
      }));
    }
    if (last.type === 'approval.received' && last.step_id) {
      setApprovalSteps(prev => {
        const cur = prev[last.step_id];
        if (!cur) return prev;
        const decision = last.decision === 'approved' ? 'APPROVED'
          : last.decision === 'rejected' ? 'REJECTED'
          : last.decision === 'escalated' ? 'ESCALATED'
          : last.decision === 'auto_approved_timeout' ? 'APPROVED'
          : 'APPROVED';
        return { ...prev, [last.step_id]: { ...cur, status: decision as ApprovalStep['status'] } };
      });
    }
    if (last.type === 'pir.streaming') setPirContent(prev => prev + (last.content || ''));
    if (last.type === 'jira.ticket_created') setJiraTicket({ ticket_id: last.ticket_id, ticket_url: last.ticket_url });
  });

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [agentMessages, toolCalls]);

  const attackTechniques: AttackTechnique[] = useMemo(() => {
    const triage = incident?.triage_result;
    return triage?.attack_techniques ?? [];
  }, [incident]);

  const verdict = incident?.triage_result?.verdict;

  return (
    <div className="min-h-screen bg-warroom-bg text-gray-200">
      <header className="border-b border-warroom-border px-4 sm:px-6 py-3 flex flex-wrap gap-2 items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/dashboard" className="text-gray-400 hover:text-white">← Dashboard</Link>
          <span className="text-sm text-gray-500">|</span>
          <span className="text-sm font-mono">{incidentId.slice(0, 12)}</span>
          {incident && (
            <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${
              incident.severity === 'P1_CRITICAL' ? 'bg-red-600' :
              incident.severity === 'P2_HIGH' ? 'bg-orange-500' :
              incident.severity === 'P3_MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
            }`}>{incident.severity}</span>
          )}
          {verdict && (
            <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${VERDICT_COLORS[verdict] || 'bg-gray-600'}`}>
              {VERDICT_LABEL[verdict] || verdict}
            </span>
          )}
          {incident && incident.alert_count > 1 && (
            <span
              className="px-2 py-0.5 rounded text-xs font-bold bg-warroom-anlst/20 border border-warroom-anlst/40 text-warroom-anlst"
              title="Correlated alerts folded into this incident by the dedup engine"
            >
              ×{incident.alert_count} alerts folded
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 text-sm">
          <Link href="/analytics" className="text-gray-400 hover:text-white">Analytics</Link>
          <Link href="/security" className="text-gray-400 hover:text-white">Security</Link>
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-warroom-success animate-pulse-dot' : 'bg-red-500'}`} />
          <span className="text-xs text-gray-400">{connected ? 'Live' : 'Disconnected'}</span>
        </div>
      </header>

      {(loadError || actionError) && (
        <div role="alert" className="mx-4 mt-3 bg-red-500/10 border border-red-500/40 text-red-300 rounded-lg p-3 text-sm">
          {loadError || actionError}
        </div>
      )}
      <main className="grid grid-cols-1 lg:grid-cols-4 gap-4 p-4 lg:h-[calc(100vh-60px)]">
        {/* War Room Chat */}
        <div className="lg:col-span-3 flex flex-col gap-4 overflow-hidden">
          {/* MITRE ATT&CK Mapping */}
          {attackTechniques.length > 0 && (
            <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-sm font-semibold text-gray-300">MITRE ATT&CK Mapping</span>
                <span className="text-xs text-gray-500">(triaged by CMDR)</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {attackTechniques.map((t, i) => (
                  <a
                    key={i}
                    href={`https://attack.mitre.org/techniques/${(t.technique_id || '').replace('.', '/')}/`}
                    target="_blank"
                    rel="noreferrer"
                    className={`px-2 py-1 rounded text-xs border ${ATTACK_TACTIC_COLORS[t.tactic || ''] || 'bg-gray-500/20 border-gray-500/40 text-gray-300'} hover:opacity-80 transition`}
                    title={t.tactic ? `Tactic: ${t.tactic}` : undefined}
                  >
                    <span className="font-mono font-bold">{t.technique_id}</span>
                    {t.name && <span className="ml-1">· {t.name}</span>}
                    {typeof t.confidence === 'number' && (
                      <span className="ml-1 text-gray-400">({Math.round(t.confidence * 100)}%)</span>
                    )}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Thinking Panel */}
          <ThinkingPanel chunks={thinkingChunks} expanded={thinkingExpanded} onToggle={() => setThinkingExpanded(!thinkingExpanded)} />

          {/* Agent Messages */}
          <div ref={chatRef} className="flex-1 overflow-y-auto space-y-2 pr-2">
            {agentMessages.map((msg, i) => <AgentMessage key={i} event={msg} />)}
            {toolCalls.filter(t => t.type === 'tool.called').map((tc, i) => (
              <ToolCallEntry
                key={`tool-${i}`}
                event={tc}
                result={toolResults[`${tc.tool}|${tc.round}`]}
              />
            ))}
          </div>

          {/* Approval Cards */}
          {Object.values(approvalSteps).length > 0 && (
            <div className="space-y-2">
              {Object.values(approvalSteps)
                .sort((a, b) => a.step_number - b.step_number)
                .map(step => (
                  <ApprovalCard key={step.step_id} step={step} />
                ))}
            </div>
          )}

          {/* PIR Stream */}
          {pirContent && <PIRStream content={pirContent} jiraTicket={jiraTicket} />}
        </div>

        {/* Agent Status Sidebar */}
        <div className="space-y-4">
          <AgentStatusPanel events={liveEvents} />
          {incident && (
            <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Incident</h3>
              <div className="text-xs space-y-1">
                <div><span className="text-gray-500">Service:</span> {incident.affected_service}</div>
                <div><span className="text-gray-500">Status:</span> {incident.status}</div>
                <div><span className="text-gray-500">Source:</span> {incident.source}</div>
                <div><span className="text-gray-500">Category:</span> {incident.category}</div>
                {incident.triage_result?.verdict && (
                  <div><span className="text-gray-500">Verdict:</span> {VERDICT_LABEL[incident.triage_result.verdict] || incident.triage_result.verdict}</div>
                )}
                <div className="text-gray-500 mt-2 break-words">{incident.alert_message}</div>
              </div>
            </div>
          )}

          {/* Correlated alerts (dedup engine) */}
          {incident && incident.alert_count > 1 && (
            <div className="bg-warroom-surface border border-warroom-anlst/30 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-warroom-anlst mb-2">
                🔗 Correlated Alerts · ×{incident.alert_count}
              </h3>
              <p className="text-xs text-gray-400 mb-2">
                {incident.alert_count} raw alerts folded into this one incident instead of
                {' '}{incident.alert_count} separate investigations.
              </p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {(Array.isArray(incident.related_signals) ? incident.related_signals : []).slice(-6).reverse().map((s: ApiRecord, i: number) => (
                  <div key={i} className="text-xs border-l-2 border-warroom-anlst/40 pl-2">
                    <span className="text-warroom-anlst font-mono">{s.reason}</span>
                    <span className="text-gray-500"> · {s.source}</span>
                    <div className="text-gray-400 truncate">{s.alert_message}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threat Hunt */}
          <HuntPanel hunt={hunt} loading={huntLoading} onGenerate={runHunt} />

          {/* Detection Rule */}
          <DetectionRulePanel rule={detectionRule} loading={detectionLoading} onGenerate={runDetectionRule} onCopy={copyYaml} />

          {/* Triage Feedback */}
          <FeedbackPanel incidentId={incidentId} />

          {/* STIX Export */}
          <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
            <h3 className="text-sm font-semibold text-gray-400 mb-2">Export</h3>
            <a
              href={`${process.env.NEXT_PUBLIC_API_URL || ''}/api/v1/incidents/${incidentId}/export/stix`}
              className="text-xs text-warroom-strat hover:underline"
              download
            >
              Export STIX 2.1
            </a>
          </div>

          {jiraTicket?.ticket_id && (
            <div className="bg-warroom-surface border border-warroom-chron/30 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">JIRA Ticket</h3>
              <a
                href={jiraTicket.ticket_url || '#'}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-warroom-chron hover:underline font-mono"
              >
                {jiraTicket.ticket_id}
              </a>
              <div className="text-xs text-gray-500 mt-1">Created via SentinelForge MCP</div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function ThinkingPanel({ chunks, expanded, onToggle }: { chunks: string[]; expanded: boolean; onToggle: () => void }) {
  if (chunks.length === 0) return null;
  return (
    <div className="thinking-panel p-4">
      <button onClick={onToggle} className="flex items-center gap-2 w-full text-left">
        <span className="w-2 h-2 rounded-full bg-warroom-thinking animate-pulse-dot" />
        <span className="text-sm font-semibold text-warroom-thinking">🔮 LIVE REASONING TRACE</span>
        <span className="text-xs bg-warroom-thinking/20 px-2 py-0.5 rounded text-warroom-thinking">open model · reasoning</span>
        <span className="ml-auto text-gray-500 text-xs">{expanded ? '▼' : '▶'}</span>
      </button>
      {expanded && (
        <div className="mt-3 text-sm text-gray-300 max-h-48 overflow-y-auto leading-relaxed">
          <span className="typing-cursor">{chunks.join('')}</span>
        </div>
      )}
    </div>
  );
}

const HUNT_PRIORITY_COLORS: Record<string, string> = {
  HIGH: 'bg-red-500/20 border-red-500/40 text-red-300',
  MEDIUM: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300',
  LOW: 'bg-gray-500/20 border-gray-500/40 text-gray-300',
};

function HuntPanel({ hunt, loading, onGenerate }: { hunt: HuntPlan | null; loading: boolean; onGenerate: () => void }) {
  return (
    <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-gray-300">🎯 Threat Hunt</h3>
        <button
          onClick={onGenerate}
          disabled={loading}
          className="text-xs px-2 py-1 rounded bg-warroom-anlst/20 border border-warroom-anlst/40 text-warroom-anlst hover:bg-warroom-anlst/30 disabled:opacity-50"
        >
          {loading ? 'Hunting…' : hunt ? 'Regenerate' : 'Generate hunt'}
        </button>
      </div>
      {!hunt && !loading && (
        <p className="text-xs text-gray-500">
          Turn this incident&apos;s ATT&amp;CK techniques into proactive hunt hypotheses with runnable queries.
        </p>
      )}
      {hunt && (
        <div className="space-y-3 max-h-[26rem] overflow-y-auto">
          {hunt.summary && <p className="text-xs text-gray-400">{hunt.summary}</p>}
          {hunt.hypotheses.map((h, i) => (
            <div key={i} className="border border-warroom-border rounded p-2">
              <div className="flex items-start gap-2">
                <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold border ${HUNT_PRIORITY_COLORS[h.priority || 'MEDIUM']}`}>
                  {h.priority || 'MEDIUM'}
                </span>
                <span className="text-xs font-semibold text-gray-200">{h.title}</span>
              </div>
              {h.mitre_technique_id && (
                <div className="text-[10px] text-gray-500 mt-1 font-mono">
                  {h.mitre_technique_id} {h.mitre_technique_name} · {h.tactic}
                </div>
              )}
              {h.rationale && <p className="text-[11px] text-gray-400 mt-1">{h.rationale}</p>}
              {(h.queries || []).map((q, j) => (
                <div key={j} className="mt-2">
                  <div className="text-[10px] text-warroom-anlst uppercase font-bold">{q.platform}</div>
                  <pre className="text-[10px] text-gray-300 bg-black/40 rounded p-1.5 overflow-x-auto whitespace-pre-wrap">{q.query}</pre>
                </div>
              ))}
              {h.expected_findings && (
                <p className="text-[10px] text-gray-500 mt-1"><span className="text-gray-400">Expect:</span> {h.expected_findings}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FeedbackPanel({ incidentId }: { incidentId: string }) {
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  const handleFeedback = async (verdict: string) => {
    setError('');
    try {
      await submitFeedback(incidentId, verdict);
      setSubmitted(true);
    } catch (err) {
      setError(errorMessage(err, 'Could not record feedback'));
    }
  };

  if (submitted) {
    return (
      <div className="bg-warroom-surface border border-warroom-success/30 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-400 mb-1">Triage Feedback</h3>
        <p className="text-xs text-warroom-success">recorded ✓</p>
      </div>
    );
  }

  return (
    <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-400 mb-2">Was this triage right?</h3>
      <div className="flex flex-wrap gap-2">
        <button onClick={() => handleFeedback('TRUE_POSITIVE')} className="text-xs px-2 py-1 rounded bg-red-500/20 border border-red-500/40 text-red-300 hover:bg-red-500/30">✓ TP</button>
        <button onClick={() => handleFeedback('FALSE_POSITIVE')} className="text-xs px-2 py-1 rounded bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30">✗ FP</button>
        <button onClick={() => handleFeedback('BENIGN_ANOMALY')} className="text-xs px-2 py-1 rounded bg-yellow-500/20 border border-yellow-500/40 text-yellow-300 hover:bg-yellow-500/30">~ Benign</button>
        <button onClick={() => handleFeedback('NEEDS_HUMAN')} className="text-xs px-2 py-1 rounded bg-orange-500/20 border border-orange-500/40 text-orange-300 hover:bg-orange-500/30">? Needs human</button>
      </div>
      {error && <p role="alert" className="text-xs text-red-400 mt-2">{error}</p>}
    </div>
  );
}

function DetectionRulePanel({ rule, loading, onGenerate, onCopy }: {
  rule: { rule: ApiRecord; yaml: string; path: string } | null;
  loading: boolean;
  onGenerate: () => void;
  onCopy: () => void;
}) {
  return (
    <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-gray-300">Detection Rule</h3>
        <button
          onClick={onGenerate}
          disabled={loading}
          className="text-xs px-2 py-1 rounded bg-warroom-strat/20 border border-warroom-strat/40 text-warroom-strat hover:bg-warroom-strat/30 disabled:opacity-50"
        >
          {loading ? 'Generating…' : rule ? 'Regenerate' : 'Generate'}
        </button>
      </div>
      {!rule && !loading && (
        <p className="text-xs text-gray-500">
          Generate a Sigma detection rule from this incident&apos;s IOCs and MITRE techniques.
        </p>
      )}
      {rule && (
        <div>
          {rule.rule?.title && (
            <p className="text-xs text-gray-300 font-semibold mb-2">{rule.rule.title}</p>
          )}
          <pre className="text-[10px] text-gray-300 bg-black/40 rounded p-2 overflow-x-auto max-h-48 whitespace-pre-wrap">{rule.yaml}</pre>
          <button
            onClick={onCopy}
            className="mt-2 text-xs px-2 py-1 rounded bg-warroom-surface border border-warroom-border text-gray-400 hover:text-gray-200"
          >
            Copy YAML
          </button>
        </div>
      )}
    </div>
  );
}

function AgentMessage({ event }: { event: SSEEvent }) {
  const persona = event.persona || 'AGENT';
  const color = PERSONA_COLORS[persona] || 'text-gray-400';
  const dot = PERSONA_DOTS[persona] || 'bg-gray-400';
  return (
    <div className="agent-message flex gap-3 py-2">
      <div className="flex flex-col items-center pt-1">
        <span className={`w-3 h-3 rounded-full ${dot}`} />
      </div>
      <div className="flex-1">
        <span className={`text-xs font-bold ${color}`}>[{persona}]</span>
        <span className="text-sm text-gray-300 ml-2">{event.text}</span>
      </div>
    </div>
  );
}

function ToolCallEntry({ event, result }: { event: SSEEvent; result?: SSEEvent }) {
  const [expanded, setExpanded] = useState(false);
  const resultPayload = result?.payload || result?.result;
  const preview = useMemo(() => {
    if (resultPayload === undefined) return undefined;
    if (typeof resultPayload === 'string') return resultPayload.slice(0, 1200);
    try { return JSON.stringify(resultPayload, null, 2).slice(0, 1200); } catch { return String(resultPayload).slice(0, 1200); }
  }, [resultPayload]);

  return (
    <div className="tool-entry pl-4 pr-3 py-2 ml-6">
      <div className="flex items-center gap-2">
        <span className="text-xs font-bold text-warroom-anlst">[ANLST]</span>
        <span className="text-xs text-gray-400">→</span>
        <span className="text-sm text-gray-300">{event.tool || 'tool'}</span>
        {result ? <span className="text-warroom-success text-xs">✓</span>
                : <span className="text-yellow-400 text-xs animate-pulse">…</span>}
        {event.args && (
          <span className="text-xs text-gray-500 font-mono truncate max-w-xs">
            {(() => { try { return JSON.stringify(event.args).slice(0, 80); } catch { return ''; } })()}
          </span>
        )}
        {result && (
          <button onClick={() => setExpanded(!expanded)} className="ml-auto text-xs text-gray-500 hover:text-gray-300">
            {expanded ? 'hide' : 'show'}
          </button>
        )}
      </div>
      {expanded && preview && (
        <pre className="mt-2 text-xs text-gray-400 bg-warroom-bg rounded p-2 overflow-x-auto max-h-48">{preview}</pre>
      )}
    </div>
  );
}

function ApprovalCard({ step }: { step: ApprovalStep }) {
  const [ratOpen, setRatOpen] = useState(false);
  const [rationale, setRationale] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const handle = async (action: 'approved' | 'rejected' | 'escalated') => {
    if (!step.step_id || busy) return;
    setBusy(true);
    setError('');
    try {
      if (action === 'approved') await approveStep(step.step_id, rationale);
      else if (action === 'rejected') await rejectStep(step.step_id, rationale || 'Rejected by operator');
      else await escalateStep(step.step_id, rationale || 'Escalated by operator');
      // The card flips state when the approval.received event arrives over SSE.
    } catch (err) {
      setError(errorMessage(err, 'Decision was not recorded'));
    } finally {
      setBusy(false);
    }
  };

  if (step.status !== 'AWAITING_APPROVAL') {
    const tone =
      step.status === 'APPROVED' ? 'border-warroom-success/30 text-warroom-success'
      : step.status === 'REJECTED' ? 'border-red-500/30 text-red-400'
      : 'border-warroom-warning/30 text-warroom-warning';
    return (
      <div className={`bg-warroom-surface border ${tone} rounded-lg p-4 text-center text-sm`}>
        Step {step.step_number} — {step.status.replace('_', ' ')}
      </div>
    );
  }

  return (
    <div className="approval-card p-5">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-warroom-warning font-bold">⚠️ APPROVAL REQUIRED</span>
        <span className="text-xs text-gray-400">— Step {step.step_number}</span>
        {step.action_type && (
          <span className="text-xs text-gray-500 font-mono ml-1">[{step.action_type}]</span>
        )}
      </div>
      <div className="text-sm mb-3">{step.description}</div>
      <div className="flex items-center gap-4 text-xs text-gray-400 mb-4">
        <span>Risk: <span className="text-warroom-warning font-bold">{step.risk_level}</span></span>
        {step.rollback && <span>Rollback: available</span>}
      </div>
      <div className="mb-3">
        <button onClick={() => setRatOpen(!ratOpen)} className="text-xs text-gray-400 hover:text-gray-200 underline">
          {ratOpen ? 'hide rationale' : 'add rationale'}
        </button>
        {ratOpen && (
          <textarea
            aria-label="Approval rationale"
            value={rationale}
            onChange={e => setRationale(e.target.value)}
            placeholder="Auditor rationale (recorded in the immutable audit log)..."
            className="w-full mt-2 bg-warroom-bg border border-warroom-border rounded p-2 text-sm resize-none h-16 focus:outline-none focus:border-warroom-tool"
          />
        )}
      </div>
      <div className="flex gap-3">
        <button type="button" disabled={busy} onClick={() => handle('approved')} className="flex-1 disabled:opacity-50 py-2 px-4 bg-warroom-success/20 border border-warroom-success/40 rounded text-sm font-bold text-warroom-success hover:bg-warroom-success/30 transition">
          ✓ APPROVE
        </button>
        <button type="button" disabled={busy} onClick={() => handle('rejected')} className="flex-1 disabled:opacity-50 py-2 px-4 bg-warroom-alert/20 border border-warroom-alert/40 rounded text-sm font-bold text-warroom-alert hover:bg-warroom-alert/30 transition">
          ✗ REJECT
        </button>
        <button type="button" disabled={busy} onClick={() => handle('escalated')} className="flex-1 disabled:opacity-50 py-2 px-4 bg-warroom-warning/20 border border-warroom-warning/40 rounded text-sm font-bold text-warroom-warning hover:bg-warroom-warning/30 transition">
          ↑ ESCALATE
        </button>
      </div>
      {error && <p role="alert" className="text-xs text-red-400 mt-2">{error}</p>}
    </div>
  );
}

function PIRStream({ content, jiraTicket }: { content: string; jiraTicket?: { ticket_id?: string; ticket_url?: string } | null }) {
  return (
    <div className="bg-warroom-surface border border-warroom-chron/30 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="w-2 h-2 rounded-full bg-warroom-chron animate-pulse-dot" />
        <span className="text-sm font-semibold text-warroom-chron">[CHRON] Security Incident Report</span>
      </div>
      <div className="prose prose-invert prose-sm max-h-64 overflow-y-auto">
        <PIRMarkdown content={content} />
      </div>
      {jiraTicket?.ticket_id && (
        <div className="mt-3 pt-3 border-t border-warroom-border text-xs text-gray-400">
          Filed as{' '}
          <a href={jiraTicket.ticket_url || '#'} target="_blank" rel="noreferrer" className="text-warroom-chron font-mono hover:underline">
            {jiraTicket.ticket_id}
          </a>
          {' '}via the SentinelForge MCP server.
        </div>
      )}
    </div>
  );
}

// Minimal markdown renderer using react-markdown to render the streamed PIR.
function PIRMarkdown({ content }: { content: string }) {
  return <ReactMarkdown>{content}</ReactMarkdown>;
}

function AgentStatusPanel({ events }: { events: SSEEvent[] }) {
  const agents = ['CMDR', 'ANLST', 'STRAT', 'OPS', 'CHRON'];
  const getStatus = (persona: string) => {
    const msgs = events.filter(e => e.persona === persona);
    if (msgs.length === 0) return { status: 'Standby', active: false };
    return { status: 'Active', active: true };
  };

  return (
    <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-400 mb-3">Agent Status</h3>
      <div className="space-y-2">
        {agents.map(a => {
          const { status, active } = getStatus(a);
          return (
            <div key={a} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${PERSONA_DOTS[a]}`} />
                <span className={`font-bold ${PERSONA_COLORS[a]}`}>{a}</span>
              </div>
              <span className={active ? 'text-warroom-success' : 'text-gray-500'}>
                {active ? '●' : '○'} {status}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}