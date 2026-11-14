'use client';

import { useCallback, useEffect, useState } from 'react';
import { Clock, Cpu, Download, ExternalLink, Layers, Server, Target } from 'lucide-react';
import {
  type ApiRecord,
  apiUrl,
  fetchAnalytics,
  fetchByService,
  fetchByVerdict,
  fetchMTTR,
  fetchSummary,
  fetchTopTechniques,
} from '@/lib/api';
import { VERDICT_META, attackUrl, humanize } from '@/lib/format';
import AppShell from '@/components/AppShell';
import ErrorNotice from '@/components/ErrorNotice';
import { Card, LoadingBlock, PageHeader, Skeleton, Stat } from '@/components/ui';

interface VerdictRow { verdict: string; count: number }
interface ServiceRow { affected_service: string; count: number }
interface UsageRow { qwen_model: string; input_tokens: number; output_tokens: number; thinking_tokens: number; calls: number }

function formatDuration(seconds: number): string {
  if (!seconds) return '0s';
  if (seconds < 90) return `${Math.round(seconds)}s`;
  const m = seconds / 60;
  if (m < 90) return `${Math.round(m)}m`;
  return `${(m / 60).toFixed(1)}h`;
}

export default function AnalyticsPage() {
  const [summary, setSummary] = useState<ApiRecord | null>(null);
  const [mttr, setMTTR] = useState<ApiRecord | null>(null);
  const [byService, setByService] = useState<ServiceRow[]>([]);
  const [verdicts, setVerdicts] = useState<VerdictRow[]>([]);
  const [techniques, setTechniques] = useState<ApiRecord[]>([]);
  const [usage, setUsage] = useState<UsageRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
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
      if (failures.length === 6) setError(failures[0]);
      setLoading(false);
    });
  }, []);

  useEffect(load, [load]);

  const n = (v: unknown) => (typeof v === 'number' ? v : 0).toLocaleString();

  return (
    <AppShell>
      <PageHeader
        title="SOC analytics"
        description="How much noise the correlation engine removes, how fast incidents are contained, and which ATT&CK techniques show up most."
        actions={
          <a href={apiUrl('/api/v1/analytics/navigator-layer')} className="btn btn-secondary btn-sm" download>
            <Download className="h-4 w-4" aria-hidden="true" />
            ATT&amp;CK Navigator layer
          </a>
        }
      />

      {loading ? (
        <LoadingBlock label="Loading analytics">
          <Skeleton className="mb-6 h-36 w-full rounded-xl" />
          <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
            {[0, 1, 2, 3].map(i => <Skeleton key={i} className="h-24 rounded-xl" />)}
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {[0, 1, 2, 3].map(i => <Skeleton key={i} className="h-48 rounded-xl" />)}
          </div>
        </LoadingBlock>
      ) : error ? (
        <ErrorNotice error={error} onRetry={load} />
      ) : (
        <div className="space-y-6">
          {/* Alert-fatigue reduction — the headline SOC efficiency metric. */}
          <section
            aria-labelledby="noise-heading"
            className="card overflow-hidden border-warroom-anlst/30 bg-gradient-to-br from-warroom-anlst/10 via-surface to-surface p-5 sm:p-6"
          >
            <div className="flex flex-wrap items-center justify-between gap-6">
              <div>
                <h2 id="noise-heading" className="eyebrow">Alert noise reduction</h2>
                <div className="mt-1 text-4xl font-semibold tabular-nums text-warroom-anlst sm:text-5xl">
                  {summary?.noise_reduction_pct ?? 0}%
                </div>
                <p className="mt-2 max-w-md text-sm text-fg-muted">
                  {n(summary?.total_alerts_ingested)} raw alerts folded into {n(summary?.total)} incidents by the correlation engine.
                </p>
              </div>
              <dl className="grid grid-cols-3 gap-4 text-center sm:gap-8">
                <div>
                  <dt className="text-xs text-fg-subtle">Alerts in</dt>
                  <dd className="text-2xl font-semibold tabular-nums">{n(summary?.total_alerts_ingested)}</dd>
                </div>
                <div>
                  <dt className="text-xs text-fg-subtle">Incidents</dt>
                  <dd className="text-2xl font-semibold tabular-nums">{n(summary?.total)}</dd>
                </div>
                <div>
                  <dt className="text-xs text-fg-subtle">Suppressed</dt>
                  <dd className="text-2xl font-semibold tabular-nums text-warroom-success">{n(summary?.alerts_folded)}</dd>
                </div>
              </dl>
            </div>
          </section>

          <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
            <Stat label="Total incidents" value={n(summary?.total)} />
            <Stat label="Resolved" value={n(summary?.resolved)} tone="text-warroom-success" />
            <Stat label="Dismissed" value={n(summary?.dismissed)} hint="False positive or benign" />
            <Stat label="Escalated" value={n(summary?.escalated)} tone="text-warroom-warning" />
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Card title="Containment" icon={<Clock className="h-4 w-4" />} titleId="mttr-heading">
              <dl className="grid grid-cols-2 gap-4">
                <div>
                  <dt className="text-xs text-fg-subtle">Mean time to resolve</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">{formatDuration(mttr?.avg_mttr_seconds ?? 0)}</dd>
                </div>
                <div>
                  <dt className="text-xs text-fg-subtle">Incidents resolved</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">{n(mttr?.resolved_count)}</dd>
                </div>
              </dl>
            </Card>

            <Card title="Verdict distribution" icon={<Layers className="h-4 w-4" />} titleId="verdict-heading">
              {verdicts.length === 0 ? (
                <p className="text-sm text-fg-subtle">No triaged incidents yet.</p>
              ) : (
                <BarList
                  label="Incidents by triage verdict"
                  rows={verdicts.map(v => ({
                    label: VERDICT_META[v.verdict]?.label ?? humanize(v.verdict),
                    count: v.count,
                    color: VERDICT_META[v.verdict]?.bar ?? 'bg-slate-500',
                  }))}
                />
              )}
            </Card>

            <Card title="Incidents by service" icon={<Server className="h-4 w-4" />} titleId="service-heading">
              {byService.length === 0 ? (
                <p className="text-sm text-fg-subtle">No incidents yet.</p>
              ) : (
                <BarList
                  label="Incidents by affected service"
                  rows={byService.map(s => ({ label: s.affected_service, count: s.count, color: 'bg-warroom-tool' }))}
                />
              )}
            </Card>

            <Card title="Top MITRE ATT&CK techniques" icon={<Target className="h-4 w-4" />} titleId="attack-heading">
              {techniques.length === 0 ? (
                <p className="text-sm text-fg-subtle">No techniques mapped yet.</p>
              ) : (
                <ul className="divide-y divide-line text-sm">
                  {techniques.map((t, i) => (
                    <li key={i} className="flex items-center gap-3 py-2 first:pt-0 last:pb-0">
                      <a
                        href={attackUrl(t.technique_id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-warroom-chron hover:underline"
                      >
                        {t.technique_id}
                        <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        <span className="sr-only">(opens MITRE ATT&amp;CK in a new tab)</span>
                      </a>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-fg">{t.name}</span>
                        <span className="block text-2xs text-fg-subtle">{t.tactic}</span>
                      </span>
                      <span className="tabular-nums text-xs text-fg-muted">{t.count}×</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card title="LLM token usage" icon={<Cpu className="h-4 w-4" />} titleId="usage-heading" className="md:col-span-2">
              {usage.length === 0 ? (
                <p className="text-sm text-fg-subtle">
                  No LLM calls recorded yet. With no <code className="text-xs">LLM_API_KEY</code> set, agents run on
                  deterministic heuristics.
                </p>
              ) : (
                <div className="-mx-4 overflow-x-auto sm:mx-0">
                  <table className="w-full min-w-[480px] text-left text-sm">
                    <thead className="text-2xs uppercase tracking-wider text-fg-subtle">
                      <tr>
                        <th scope="col" className="px-4 py-2 font-semibold sm:px-0">Model</th>
                        <th scope="col" className="px-2 py-2 text-right font-semibold">Calls</th>
                        <th scope="col" className="px-2 py-2 text-right font-semibold">Input</th>
                        <th scope="col" className="px-2 py-2 text-right font-semibold">Output</th>
                        <th scope="col" className="px-4 py-2 text-right font-semibold sm:px-0">Thinking</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {usage.map(u => (
                        <tr key={u.qwen_model}>
                          <td className="px-4 py-2 font-mono text-xs text-warroom-chron sm:px-0">{u.qwen_model}</td>
                          <td className="px-2 py-2 text-right tabular-nums">{n(u.calls)}</td>
                          <td className="px-2 py-2 text-right tabular-nums text-fg-muted">{n(u.input_tokens)}</td>
                          <td className="px-2 py-2 text-right tabular-nums text-fg-muted">{n(u.output_tokens)}</td>
                          <td className="px-4 py-2 text-right tabular-nums text-fg-muted sm:px-0">{n(u.thinking_tokens)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>

          <p className="text-xs text-fg-subtle">
            Load the Navigator layer at{' '}
            <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-fg">
              MITRE ATT&amp;CK Navigator
            </a>{' '}
            to see observed techniques on the full matrix.
          </p>
        </div>
      )}
    </AppShell>
  );
}

function BarList({ rows, label }: { rows: { label: string; count: number; color: string }[]; label: string }) {
  const max = Math.max(1, ...rows.map(r => r.count));
  const total = rows.reduce((s, r) => s + r.count, 0) || 1;
  return (
    <ul className="space-y-3" aria-label={label}>
      {rows.map((r, i) => (
        <li key={i}>
          <div className="flex justify-between gap-2 text-xs">
            <span className="truncate text-fg">{r.label}</span>
            <span className="tabular-nums text-fg-muted">
              {r.count} <span className="text-fg-subtle">· {Math.round((r.count / total) * 100)}%</span>
            </span>
          </div>
          <div className="mt-1.5 h-2 rounded-full bg-canvas" aria-hidden="true">
            <div
              className={`h-2 rounded-full ${r.color} transition-[width] duration-500`}
              style={{ width: `${Math.max(4, (r.count / max) * 100)}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}
