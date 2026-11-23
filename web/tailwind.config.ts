import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        vault: {
          canvas: '#F7F8FA',
          surface: '#FFFFFF',
          ink: '#0F172A',
          muted: '#475569',
          subtle: '#64748B',
          border: '#E2E8F0',
          well: '#F1F5F9',
          emerald: '#0F766E',
          'emerald-soft': '#ECFDF5',
          sky: '#0369A1',
          'sky-soft': '#F0F9FF',
          amber: '#B45309',
          'amber-soft': '#FFFBEB',
        },
      },
      fontFamily: {
        sans: [
          'var(--font-plus-jakarta)',
          'var(--font-noto-sans-thai)',
          'system-ui',
          '-apple-system',
          'sans-serif',
        ],
        mono: [
          'var(--font-jetbrains-mono)',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'monospace',
        ],
      },
      boxShadow: {
        vault: '0 1px 2px rgba(15, 23, 42, 0.05), 0 1px 1px rgba(15, 23, 42, 0.03)',
        'vault-elevated':
          '0 10px 30px -12px rgba(15, 23, 42, 0.08), 0 1px 2px rgba(15, 23, 42, 0.04)',
      },
    },
  },
  plugins: [],
};

export default config;
