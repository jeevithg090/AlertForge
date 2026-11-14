/** Display helpers shared by the dashboard and incident pages. */

export const SEVERITY_META: Record<string, { label: string; short: string; className: string }> = {
  P1_CRITICAL: { label: 'Critical', short: 'P1', className: 'border-red-400/50 bg-red-500/15 text-red-300' },
  P2_HIGH: { label: 'High', short: 'P2', className: 'border-orange-400/50 bg-orange-500/15 text-orange-300' },
  P3_MEDIUM: { label: 'Medium', short: 'P3', className: 'border-yellow-400/50 bg-yellow-500/10 text-yellow-300' },
  P4_LOW: { label: 'Low', short: 'P4', className: 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300' },
};

export const STATUS_META: Record<string, { label: string; className: string }> = {
  INGESTED: { label: 'Ingested', className: 'text-fg-muted' },
  TRIAGING: { label: 'Triaging', className: 'text-sky-300' },
  INVESTIGATING: { label: 'Investigating', className: 'text-cyan-300' },
  PLANNING: { label: 'Planning', className: 'text-violet-300' },
  AWAITING_APPROVAL: { label: 'Awaiting approval', className: 'text-warroom-warning' },
  EXECUTING: { label: 'Executing', className: 'text-orange-300' },
  RESOLVED: { label: 'Resolved', className: 'text-warroom-success' },
  DISMISSED: { label: 'Dismissed', className: 'text-fg-subtle' },
  ESCALATED: { label: 'Escalated', className: 'text-red-300' },
};

export const VERDICT_META: Record<string, { label: string; className: string; bar: string }> = {
  TRUE_POSITIVE: { label: 'True positive', className: 'border-red-400/50 bg-red-500/15 text-red-300', bar: 'bg-red-400' },
  FALSE_POSITIVE: {
    label: 'False positive',
    className: 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300',
    bar: 'bg-emerald-400',
  },
  BENIGN_ANOMALY: {
    label: 'Benign anomaly',
    className: 'border-yellow-400/50 bg-yellow-500/10 text-yellow-300',
    bar: 'bg-yellow-400',
  },
  NEEDS_HUMAN: { label: 'Needs human', className: 'border-orange-400/50 bg-orange-500/15 text-orange-300', bar: 'bg-orange-400' },
  UNKNOWN: { label: 'Unknown', className: 'border-line-strong bg-surface-raised text-fg-muted', bar: 'bg-slate-500' },
};

export function humanize(value: string | null | undefined): string {
  if (!value) return '—';
  const s = value.replace(/[_.]/g, ' ').toLowerCase();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

/** "just now", "4m ago", "2h ago", "3d ago". */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function attackUrl(techniqueId: string | undefined): string {
  return `https://attack.mitre.org/techniques/${(techniqueId || '').replace('.', '/')}/`;
}
