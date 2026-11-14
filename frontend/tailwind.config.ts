import type { Config } from 'tailwindcss';

/**
 * Design tokens. Surfaces and text use semantic names (canvas / surface / line /
 * fg) backed by CSS variables in globals.css; the `warroom` palette keeps the
 * project's signal colours (one per agent persona plus alert/success/warning).
 */
const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        canvas: 'rgb(var(--bg) / <alpha-value>)',
        surface: { DEFAULT: 'rgb(var(--surface) / <alpha-value>)', raised: 'rgb(var(--surface-raised) / <alpha-value>)' },
        line: { DEFAULT: 'rgb(var(--border) / <alpha-value>)', strong: 'rgb(var(--border-strong) / <alpha-value>)' },
        fg: { DEFAULT: 'rgb(var(--text) / <alpha-value>)', muted: 'rgb(var(--text-muted) / <alpha-value>)', subtle: 'rgb(var(--text-subtle) / <alpha-value>)' },
        warroom: {
          bg: '#0A0E1A',
          surface: '#111827',
          border: '#1F2937',
          alert: '#FF4444',
          thinking: '#8B70FF',
          tool: '#00D4FF',
          success: '#00FF88',
          warning: '#FFB800',
          cmdr: '#FF5C5C',
          anlst: '#00D4FF',
          strat: '#FFB800',
          ops: '#00FF88',
          chron: '#9D86FF',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: ['JetBrains Mono', 'Fira Code', 'SF Mono', 'ui-monospace', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      boxShadow: {
        card: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 1px 2px 0 rgba(0,0,0,0.4)',
      },
      animation: {
        'pulse-dot': 'pulse-dot 2s ease-in-out infinite',
        'fade-in': 'fade-in 0.25s ease-out',
        shimmer: 'shimmer 1.6s linear infinite',
      },
      keyframes: {
        'pulse-dot': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
        'fade-in': {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-400px 0' },
          '100%': { backgroundPosition: '400px 0' },
        },
      },
    },
  },
  plugins: [],
};

export default config;
