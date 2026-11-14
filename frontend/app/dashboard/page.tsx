'use client';

import { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { useAllIncidentsStream, SSEEvent } from '@/lib/sse';
import { ApiError, fetchIncidents, fetchPendingApprovals, ingestText } from '@/lib/api';

interface Incident {
  id: string;
  severity: string;
  status: string;
  affected_service: string;
  alert_message: string;
  created_at: string;
  alert_count?: number;
}

interface LogEntry {
  ts: string;
  event: SSEEvent;
}

const SEVERITY_COLORS: Record<string, string> = {
  P1_CRITICAL: 'bg-red-600',
  P2_HIGH: 'bg-orange-500',
  P3_MEDIUM: 'bg-yellow-500',
  P4_LOW: 'bg-green-500',
};

const STATUS_LABELS: Record<string, string> = {
  INGESTED: 'Ingested',
  TRIAGING: 'Triaging',
  INVESTIGATING: 'Investigating',
  PLANNING: 'Planning',
  AWAITING_APPROVAL: 'Awaiting Approval',
  EXECUTING: 'Executing',
  RESOLVED: 'Resolved',
  DISMISSED: 'Dismissed',
  ESCALATED: 'Escalated',
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  'incident.created': 'text-green-400',
  'triage.started': 'text-blue-400',
  'triage.complete': 'text-blue-300',
  'investigation.started': 'text-cyan-400',
  'investigation.complete': 'text-cyan-300',
  'plan.generated': 'text-purple-400',
  'approval.required': 'text-yellow-400',
  'approval.received': 'text-yellow-300',
  'step.executing': 'text-orange-400',
  'step.complete': 'text-green-300',
  'step.failed': 'text-red-400',
  'incident.resolved': 'text-green-400',
  'tool.called': 'text-gray-400',
  'agent.message': 'text-gray-300',
  'pir.complete': 'text-indigo-400',
  'thinking.chunk': 'text-purple-300',
  'rollback.triggered': 'text-red-400',
};

function formatTime(iso: string) {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function DashboardPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [approvalCount, setApprovalCount] = useState(0);
  const [eventLog, setEventLog] = useState<LogEntry[]>([]);
  const eventLogRef = useRef<HTMLDivElement>(null);

  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    fetchIncidents()
      .then(data => {
        if (data.incidents) {
          setIncidents(data.incidents);
          setApprovalCount(data.incidents.filter((i: Incident) => i.status === 'AWAITING_APPROVAL').length);
        }
      })
      .catch(err => setLoadError(err instanceof ApiError ? err.message : 'Could not load incidents'))
      .finally(() => setLoading(false));
    fetchPendingApprovals().then(data => {
      // API returns { pending: [...], count: N } — not an array.
      if (data && typeof data.count === 'number') setApprovalCount(data.count);
    }).catch(() => {});
  }, []);

  // Handle every live event (not just the latest render's) so bursts aren't dropped.
  const { connected } = useAllIncidentsStream((last: SSEEvent) => {
    if (last.type === 'incident.created' && last.incident_id) {
      const newId: string = last.incident_id;
      setIncidents(prev =>
        prev.some(i => i.id === newId)
          ? prev
          : [
              {
                id: newId,
                severity: last.severity || 'P3_MEDIUM',
                status: 'INGESTED',
                affected_service: last.affected_service || 'unknown',
                alert_message: last.alert_message || '',
                created_at: new Date().toISOString(),
              },
              ...prev,
            ],
      );
    }
    setEventLog(prev => [...prev.slice(-199), { ts: new Date().toISOString(), event: last }]);
  });

  useEffect(() => {
    if (eventLogRef.current) {
      eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight;
    }
  }, [eventLog]);

  const active = incidents.filter(i => !['RESOLVED', 'DISMISSED'].includes(i.status));
  const resolved = incidents.filter(i => i.status === 'RESOLVED');
  const awaiting = incidents.filter(i => i.status === 'AWAITING_APPROVAL');

  return (
    <div className="min-h-screen bg-warroom-bg text-gray-200">
      <header className="border-b border-warroom-border px-4 sm:px-6 py-4 flex flex-wrap gap-3 items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl" aria-hidden="true">🛡️</span>
          <h1 className="text-lg sm:text-xl font-bold tracking-wide">SENTINELFORGE SOC WAR ROOM</h1>
        </div>
        <nav aria-label="Primary" className="flex flex-wrap items-center gap-4 text-sm">
          <Link href="/analytics" className="text-gray-400 hover:text-white">Analytics</Link>
          <Link href="/security" className="text-gray-400 hover:text-white">Security</Link>
          <span className="text-gray-400">
            Active: <span className="text-warroom-alert font-bold">{active.length}</span>
          </span>
          <span className="text-gray-400">
            Resolved: <span className="text-warroom-success font-bold">{resolved.length}</span>
          </span>
          {Math.max(approvalCount, awaiting.length) > 0 && (
            <span className="text-gray-400">
              Approvals: <span className="text-warroom-warning font-bold animate-pulse">{Math.max(approvalCount, awaiting.length)}</span>
            </span>
          )}
          <span
            role="status"
            aria-label={connected ? 'Live stream connected' : 'Live stream disconnected'}
            title={connected ? 'Live stream connected' : 'Live stream disconnected'}
            className={`w-2 h-2 rounded-full ${connected ? 'bg-warroom-success animate-pulse-dot' : 'bg-red-500'}`}
          />
        </nav>
      </header>

      <main className="p-4 sm:p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incident Feed */}
        <div className="lg:col-span-2">
          <h2 className="text-lg font-semibold mb-4 text-gray-300">Incident Feed</h2>
          <div className="space-y-3 max-h-[calc(100vh-220px)] overflow-y-auto pr-2">
            {loading && (
              <div className="text-gray-500 text-center py-12" role="status">Loading incidents…</div>
            )}
            {loadError && (
              <div role="alert" className="bg-red-500/10 border border-red-500/40 text-red-300 rounded-lg p-4 text-sm">
                {loadError}. Is the backend running on {process.env.NEXT_PUBLIC_API_URL || 'this origin'}?
              </div>
            )}
            {!loading && !loadError && incidents.length === 0 && (
              <div className="text-gray-500 text-center py-12 border border-warroom-border rounded-lg">
                No incidents yet. Fire a demo alert to get started.
              </div>
            )}
            {incidents.map(inc => (
              <Link
                key={inc.id}
                href={`/incidents/${inc.id}`}
                className={`block bg-warroom-surface border rounded-lg p-4 hover:border-warroom-tool transition-colors animate-fade-in ${
                  inc.status === 'AWAITING_APPROVAL' ? 'border-warroom-warning/50' :
                  inc.status === 'RESOLVED' ? 'border-warroom-success/20' : 'border-warroom-border'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${SEVERITY_COLORS[inc.severity] || 'bg-gray-500'}`}>
                      {inc.severity}
                    </span>
                    <span className="text-xs text-gray-400 font-mono">{inc.id.slice(0, 8)}</span>
                    {inc.status === 'AWAITING_APPROVAL' && (
                      <span className="text-xs text-warroom-warning">⚠️</span>
                    )}
                  </div>
                  <span className={`text-xs ${
                    inc.status === 'AWAITING_APPROVAL' ? 'text-warroom-warning font-bold' :
                    inc.status === 'RESOLVED' ? 'text-warroom-success' :
                    'text-gray-500'
                  }`}>
                    {STATUS_LABELS[inc.status] || inc.status}
                  </span>
                </div>
                <div className="font-medium text-sm flex items-center gap-2">
                  {inc.affected_service}
                  {(inc.alert_count ?? 1) > 1 && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-warroom-anlst/20 border border-warroom-anlst/40 text-warroom-anlst" title="Correlated alerts folded by the dedup engine">
                      ×{inc.alert_count}
                    </span>
                  )}
                </div>
                <div className="text-xs text-gray-400 mt-1 truncate">{inc.alert_message}</div>
                <div className="text-xs text-gray-600 mt-1">{formatTime(inc.created_at)}</div>
              </Link>
            ))}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Quick Actions */}
          <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4 space-y-3">
            <QuickIngest />
            <Link
              href="/security"
              className="block w-full text-center py-2 px-4 bg-warroom-thinking/20 border border-warroom-thinking/40 rounded text-sm hover:bg-warroom-thinking/30 transition"
            >
              Security Controls
            </Link>
          </div>

          {/* Event Log */}
          <div className="bg-warroom-surface border border-warroom-border rounded-lg">
            <div className="px-4 py-3 border-b border-warroom-border flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-300">Event Log</h3>
              <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-warroom-success animate-pulse-dot' : 'bg-red-500'}`} />
            </div>
            <div
              ref={eventLogRef}
              className="overflow-y-auto p-2 space-y-0.5 max-h-[400px]"
            >
              {eventLog.length === 0 && (
                <div className="text-gray-600 text-xs text-center py-4">Waiting for events...</div>
              )}
              {eventLog.map((entry, i) => {
                const evt = entry.event;
                return (
                <div key={i} className="flex items-start gap-2 text-xs py-1 px-2 rounded hover:bg-warroom-bg/50 transition-colors">
                  <span className="text-gray-600 font-mono whitespace-nowrap w-16 shrink-0">
                    {formatTime(entry.ts)}
                  </span>
                  <span className={`font-semibold shrink-0 ${EVENT_TYPE_COLORS[evt.type] || 'text-gray-400'}`}>
                    {evt.type}
                  </span>
                  {evt.incident_id && (
                    <span className="text-gray-600 font-mono shrink-0">
                      {evt.incident_id.slice(0, 8)}
                    </span>
                  )}
                  {evt.persona && (
                    <span className="text-gray-500 shrink-0">[{evt.persona}]</span>
                  )}
                  {evt.text && (
                    <span className="text-gray-400 truncate">{evt.text}</span>
                  )}
                  {evt.tool && (
                    <span className="text-gray-500 truncate">{evt.tool}</span>
                  )}
                  {evt.severity && (
                    <span className={`shrink-0 ${
                      evt.severity === 'P1_CRITICAL' ? 'text-red-400' :
                      evt.severity === 'P2_HIGH' ? 'text-orange-400' :
                      'text-gray-500'
                    }`}>{evt.severity}</span>
                  )}
                  {evt.risk_level && (
                    <span className="text-yellow-400 shrink-0">{evt.risk_level}</span>
                  )}
                  {evt.step_number && (
                    <span className="text-gray-500 shrink-0">step {evt.step_number}</span>
                  )}
                </div>
                );
              })}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function QuickIngest() {
  const [text, setText] = useState('');
  const [status, setStatus] = useState('');

  const submit = async () => {
    if (!text.trim()) return;
    setStatus('Sending...');
    try {
      const data = await ingestText(text);
      if (!data.accepted) setStatus(`✗ ${data.reason}`);
      else if (data.correlated_into) setStatus(`✓ Folded into ${data.correlated_into.slice(0, 8)}`);
      else setStatus(`✓ Incident ${data.incident_id?.slice(0, 8)}`);
      setText('');
    } catch (err) {
      setStatus(`✗ ${err instanceof ApiError ? err.message : 'Request failed'}`);
    }
  };

  return (
    <div>
      <label htmlFor="quick-ingest" className="text-xs text-gray-400 block mb-1">Paste Alert Text</label>
      <textarea
        id="quick-ingest"
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder="SIEM/EDR alert JSON or plain text: 'failed password from 193.32.162.144 ...'"
        className="w-full bg-warroom-bg border border-warroom-border rounded p-2 text-sm resize-none h-20 focus:outline-none focus:border-warroom-tool font-mono"
      />
      <button
        type="button"
        onClick={submit}
        disabled={!text.trim() || status === 'Sending...'}
        className="w-full mt-2 py-2 px-4 bg-warroom-tool/20 border border-warroom-tool/40 rounded text-sm hover:bg-warroom-tool/30 transition disabled:opacity-50"
      >
        Submit Finding
      </button>
      {status && <div className="text-xs text-gray-400 mt-1" role="status">{status}</div>}
    </div>
  );
}
