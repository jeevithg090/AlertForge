import { ImageResponse } from 'next/og';

export const alt = 'SentinelForge — Autonomous SOC War Room';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

/** Social preview card rendered at build time from the brand colours. */
export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '80px',
          background: 'linear-gradient(135deg, #0A0E1A 0%, #111827 60%, #1B1640 100%)',
          color: '#E5E7EB',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <svg width="96" height="96" viewBox="0 0 32 32">
            <path d="M16 2.5 4.5 6.8v8.4c0 7.2 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.1 11.5-14.3V6.8L16 2.5Z" fill="#00D4FF" />
            <path d="M16 7.5 8.5 10.3v5c0 4.6 3.1 8 7.5 9.4 4.4-1.4 7.5-4.8 7.5-9.4v-5L16 7.5Z" fill="#0A0E1A" />
            <path d="m12 16.2 2.8 2.8 5.4-5.6" fill="none" stroke="#00FF88" strokeWidth="2.4" strokeLinecap="round" />
          </svg>
          <div style={{ fontSize: 72, fontWeight: 700, letterSpacing: -1 }}>SentinelForge</div>
        </div>
        <div style={{ marginTop: 32, fontSize: 40, color: '#00D4FF' }}>Autonomous SOC War Room</div>
        <div style={{ marginTop: 20, fontSize: 28, color: '#A3ACB9', maxWidth: 960, lineHeight: 1.4 }}>
          Agents triage, investigate and contain security alerts — a human approves every irreversible action.
        </div>
      </div>
    ),
    size,
  );
}
