import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        warroom: {
          bg: '#0A0E1A',
          surface: '#111827',
          border: '#1F2937',
          alert: '#FF4444',
          thinking: '#6B48FF',
          tool: '#00D4FF',
          success: '#00FF88',
          warning: '#FFB800',
          cmdr: '#FF4444',
          anlst: '#00D4FF',
          strat: '#FFB800',
          ops: '#00FF88',
          chron: '#6B48FF',
        },
      },
      animation: {
        'pulse-dot': 'pulse-dot 2s ease-in-out infinite',
        'fade-in': 'fade-in 0.3s ease-out',
      },
      keyframes: {
        'pulse-dot': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.3' },
        },
        'fade-in': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};

export default config;
