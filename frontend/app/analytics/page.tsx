'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ApiError,
  type ApiRecord,
  fetchAnalytics,
  fetchByService,
  fetchByVerdict,
  fetchMTTR,
  fetchSummary,
  fetchTopTechniques,
} from '@/lib/api';

interface VerdictRow { verdict: string; count: number }
interface ServiceRow { affected_service: string; count: number }
interface UsageRow { qwen_model: string; input_tokens: number; output_tokens: number; thinking_tokens: number; calls: number }

const VERDICT_COLORS: Record<string, string> = {
  TRUE_POSITIVE: 'bg-red-500',
  FALSE_POSITIVE: 'bg-green-500',
  BENIGN_ANOMALY: 'bg-yellow-500',
  NEEDS_HUMAN: 'bg-orange-500',
  UNKNOWN: 'bg-gray-500',
};

export default function AnalyticsPage() {
  const [summary, setSummary] = useState<ApiRecord | null>(null);
  const [mttr, setMTTR] = useState<ApiRecord | null>(null);
  const [byService, setByService] = useState<ServiceRow[]>([]);
  const [verdicts, setVerdicts] = useState<VerdictRow[]>([]);
  const [techniques, setTechniques] = useState<ApiRecord[]>([]);
  const [usage, setUsage] = useState<UsageRow[]>([]);
  const [loading, setLoading] = useState(true);

  const [error, setError] = useState('');

  useEffect(() => {
    // Each panel degrades independently; only a total failure is surfaced.
    const failures: unknown[] = [];
    const soft = <T,>(p: Promise<T>, fallback: T) =>
      p.catch(err => {
        failures.push(err);
        return fallback;
      });
    Promise.all([
      soft(fetchSummary(), {}),
      soft(fetchMTTR(), null),
      soft(fetchByService().then(d => d.services || []), []),
      soft(fetchByVerdict().then(d => d.verdicts || []), []),
      soft(fetchTopTechniques().then(d => d.techniques || []), []),
      soft(fetchAnalytics().then(d => d.usage || []), []),
    ]).then(([s, m, ser, v, t, u]) => {
      setSummary(s); setMTTR(m); setByService(ser); setVerdicts(v); setTechniques(t); setUsage(u);
      if (failures.length === 6) {
        const first = failures[0];
        setError(first instanceof ApiError ? first.message : 'Could not load analytics');
      }
      setLoading(false);
    });
  }, []);

  return (
    <div className="min-h-screen bg-warroom-bg text-gray-200">
      <header className="border-b border-warroom-border px-4 sm:px-6 py-4 flex flex-wrap items-center gap-3">
        <Link href="/dashboard" className="text-gray-400 hover:text-white">← Dashboard</Link>
        <span className="text-gray-500">|</span>
        <h1 className="text-xl font-bold">SOC Analytics</h1>
      </header>

      <main className="p-4 sm:p-6 max-w-6xl mx-auto space-y-6">
        {loading ? (
          <div className="text-gray-500" role="status">Loading analytics…</div>
        ) : error ? (
          <div role="alert" className="bg-red-500/10 border border-red-500/40 text-red-300 rounded-lg p-4 text-sm">
            {error}. Is the backend running?
          </div>
        ) : (
          <>
            {/* Alert-fatigue reduction — the headline SOC efficiency metric. */}
            <div className="bg-gradient-to-r from-warroom-anlst/10 to-transparent border border-warroom-anlst/30 rounded-lg p-5">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                  <div className="text-xs text-gray-400 uppercase tracking-wide">Alert Noise Reduction</div>
                  <div className="text-4xl font-bold text-warroom-anlst">{summary?.noise_reduction_pct ?? 0}%</div>
                  <div className="text-xs text-gray-500 mt-1">
                    {(summary?.total_alerts_ingested ?? 0).toLocaleString()} raw alerts folded into{' '}
                    {(summary?.total ?? 0).toLocaleString()} incidents by the correlation engine
                  </div>
                </div>
                <div className="flex flex-wrap gap-6 text-center">
                  <div>
                    <div className="text-2xl font-bold text-gray-200">{(summary?.total_alerts_ingested ?? 0).toLocaleString()}</div>
                    <div className="text-xs text-gray-500">alerts ingested</div>
                  </div>
                  <div className="text-2xl text-gray-600 self-center">→</div>
                  <div>
                    <div className="text-2xl font-bold text-gray-200">{(summary?.total ?? 0).toLocaleString()}</div>
                    <div className="text-xs text-gray-500">incidents</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-warroom-success">{(summary?.alerts_folded ?? 0).toLocaleString()}</div>
                    <div className="text-xs text-gray-500">suppressed</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Stat label="Total Findings" value={summary?.total ?? 0} />
              <Stat label="Resolved" value={summary?.resolved ?? 0} tone="text-warroom-success" />
              <Stat label="Dismissed (FP / benign)" value={summary?.dismissed ?? 0} tone="text-gray-400" />
              <Stat label="Escalated" value={summary?.escalated ?? 0} tone="text-warroom-warning" />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card title="Containment Metrics">
                <div className="text-sm space-y-1">
                  <div><span className="text-gray-500">Avg MTTR:</span> {(mttr?.avg_mttr_seconds ?? 0).toFixed(0)}s</div>
                  <div><span className="text-gray-500">Resolved count:</span> {mttr?.resolved_count ?? 0}</div>
                </div>
              </Card>

              <Card title="Verdict Distribution">
                {verdicts.length === 0 ? (
                  <div className="text-gray-500 text-sm">No triaged incidents yet.</div>
                ) : (
                  <BarList rows={verdicts.map(v => ({ label: v.verdict, count: v.count, color: VERDICT_COLORS[v.verdict] || 'bg-gray-500' }))} />
                )}
              </Card>

              <Card title="Findings by Affected Service">
                {byService.length === 0 ? (
                  <div className="text-gray-500 text-sm">No incidents yet.</div>
                ) : (
                  <BarList rows={byService.map(s => ({ label: s.affected_service, count: s.count, color: 'bg-warroom-tool' }))} />
                )}
              </Card>

              <Card title="Top MITRE ATT&CK Techniques">
                {techniques.length === 0 ? (
                  <div className="text-gray-500 text-sm">No techniques mapped yet.</div>
                ) : (
                  <div className="space-y-1 text-sm">
                    {techniques.map((t, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <a
                          href={`https://attack.mitre.org/techniques/${(t.technique_id || '').replace('.', '/')}/`}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono text-warroom-chron hover:underline"
                        >{t.technique_id}</a>
                        <span className="text-gray-300">{t.name}</span>
                        <span className="text-gray-500 text-xs">· {t.tactic}</span>
                        <span className="ml-auto text-gray-400 text-xs">{t.count}×</span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card title="ATT&CK Navigator">
                <a
                  href={`${process.env.NEXT_PUBLIC_API_URL || ''}/api/v1/analytics/navigator-layer`}
                  className="text-sm text-warroom-strat hover:underline"
                  download
                >
                  Download ATT&amp;CK Navigator layer
                </a>
                <p className="text-xs text-gray-500 mt-1">
                  Load this JSON at{' '}
                  <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noreferrer" className="underline">
                    attack-navigator
                  </a>{' '}
                  to visualize observed techniques.
                </p>
              </Card>

              <Card title="LLM Token Usage (by model)">
                {usage.length === 0 ? (
                  <div className="text-gray-500 text-sm">No LLM calls recorded yet.</div>
                ) : (
                  <div className="space-y-2 text-sm">
                    {usage.map(u => (
                      <div key={u.qwen_model}>
                        <div className="flex justify-between">
                          <span className="font-mono text-warroom-thinking">{u.qwen_model}</span>
                          <span className="text-gray-400">{u.calls} calls</span>
                        </div>
                        <div className="text-xs text-gray-500">
                          in {(u.input_tokens || 0).toLocaleString()} · out {(u.output_tokens || 0).toLocaleString()} · thinking {(u.thinking_tokens || 0).toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

function Stat({ label, value, tone = 'text-gray-200' }: { label: string; value: number; tone?: string }) {
  return (
    <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
      <div className="text-xs text-gray-500">{label}</div>
      <div className={`text-2xl font-bold ${tone}`}>{value}</div>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-warroom-surface border border-warroom-border rounded-lg p-4">
      <h2 className="text-sm font-semibold text-gray-400 mb-3">{title}</h2>
      {children}
    </div>
  );
}

function BarList({ rows }: { rows: { label: string; count: number; color: string }[] }) {
  const max = Math.max(1, ...rows.map(r => r.count));
  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i}>
          <div className="flex justify-between text-xs">
            <span className="text-gray-300">{r.label}</span>
            <span className="text-gray-500">{r.count}</span>
          </div>
          <div className="h-1.5 bg-warroom-bg rounded mt-1">
            <div className={`h-1.5 rounded ${r.color}`} style={{ width: `${(r.count / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}