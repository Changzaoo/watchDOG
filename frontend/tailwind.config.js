/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Escala neutra "near-black" (estilo fintech dark).
        dark: {
          50: '#f5f6f8',
          100: '#e6e8ec',
          700: '#242a33',
          800: '#1b2027',
          850: '#14181e',
          900: '#0d0f13',
          950: '#08090c',
        },
        // Acento da marca: laranja/gold Bitcoin.
        brand: {
          DEFAULT: '#f7931a',
          50: '#fff7ed',
          400: '#ffb454',
          500: '#f7931a',
          600: '#e07d0c',
          700: '#b4630a',
        },
        cyber: {
          blue: '#00d4ff',
          purple: '#8b5cf6',
          green: '#22c55e',
          orange: '#f7931a',
          red: '#ff3b5c',
        },
      },
      boxShadow: {
        'brand-glow': '0 0 24px rgba(247, 147, 26, 0.18)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
        'live-pulse': 'livePulse 1.6s ease-in-out infinite',
      },
      keyframes: {
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        livePulse: {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.35', transform: 'scale(0.85)' },
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
