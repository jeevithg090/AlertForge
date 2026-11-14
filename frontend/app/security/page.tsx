'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { type ApiRecord, fetchSecurityControls, fetchSecurityEvents } from '@/lib/api';
import ErrorNotice from '@/components/ErrorNotice';

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

export default function SecurityPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [controls, setControls] = useState<Control[]>([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const onError = (err: unknown) => setError(err);
    Promise.all([
      fetchSecurityEvents(50).then(d => setEvents((d.events || []) as SecurityEvent[])).catch(onError),
      fetchSecurityControls().then(d => setControls((d.controls || []) as Control[])).catch(onError),
    ]).finally(() => setLoading(false));
  }, []);

  // Group controls by category for display
  const grouped: Record<string, Control[]> = {};
  controls.forEach(c => { (grouped[c.category] ||= []).push(c); });

  return (
    <div className="min-h-screen bg-warroom-bg text-gray-200">
      <header className="border-b border-warroom-border px-4 sm:px-6 py-4 flex flex-wrap items-center gap-3">
        <Link href="/dashboard" className="text-gray-400 hover:text-white">← Dashboard</Link>
        <span className="text-gray-500">|</span>
        <span className="text-xl" aria-hidden="true">🛡️</span>
        <h1 className="text-xl font-bold">Security Controls</h1>
      </header>

      <main className="p-4 sm:p-6 max-w-4xl mx-auto space-y-6">
        {loading && <div className="text-gray-500 text-sm" role="status">Loading security controls…</div>}
        <ErrorNotice error={error} />
        {Object.entries(grouped).map(([category, items]) => (
          <section key={category} className="bg-warroom-surface border border-warroom-border rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 text-warroom-success">{category}</h2>
            <div className="space-y-2 text-sm">
              {items.map((c, i) => (
                <div key={i}>
                  <div className="flex items-center gap-2">
                    <span className={c.status === 'active' ? 'text-warroom-success' : 'text-yellow-400'}>
                      {c.status === 'active' ? '✅' : '⚠️'}
                    </span>
                    <span className="text-gray-300">{c.label}</span>
                  </div>
                  {c.note && <div className="text-xs text-gray-500 ml-6 mt-0.5">{c.note}</div>}
                </div>
              ))}
            </div>
          </section>
        ))}

        <section className="bg-warroom-surface border border-warroom-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 text-warroom-warning">Recent Security Events</h2>
          <div className="space-y-3">
            {events.length === 0 && (
              <div className="text-gray-500 text-sm text-center py-4">
                No security events yet. Send a malicious payload containing
                <code className="text-gray-400 mx-1">ignore previous instructions</code>
                to see the PromptGuard in action.
              </div>
            )}
            {events.map(ev => (
              <div key={ev.id} className="flex items-start gap-3 text-sm border-l-2 border-warroom-warning pl-3">
                <span className="text-warroom-warning">⚠️</span>
                <div>
                  <div className="font-medium">{ev.action}</div>
                  <div className="text-xs text-gray-400">{ev.timestamp}</div>
                  {ev.details?.reason && <div className="text-xs text-gray-500 mt-1">{ev.details.reason}</div>}
                </div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}