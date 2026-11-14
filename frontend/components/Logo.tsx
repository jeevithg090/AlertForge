/** SentinelForge shield mark (also used for the favicon in app/icon.svg). */
export default function Logo({ className = 'h-7 w-7' }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="sf-shield" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#00D4FF" />
          <stop offset="1" stopColor="#8B70FF" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 4.5 6.8v8.4c0 7.2 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.1 11.5-14.3V6.8L16 2.5Z" fill="url(#sf-shield)" />
      <path
        d="M16 7.5 8.5 10.3v5c0 4.6 3.1 8 7.5 9.4 4.4-1.4 7.5-4.8 7.5-9.4v-5L16 7.5Z"
        fill="#0A0E1A"
      />
      <path d="m12 16.2 2.8 2.8 5.4-5.6" fill="none" stroke="#00FF88" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
