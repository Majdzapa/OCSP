import { createTheme } from '@mantine/core'

export const mantineTheme = createTheme({
  primaryColor: 'indigo',
  fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', 'Fira Code', monospace",
  defaultRadius: 'md',
  colors: {
    dark: [
      '#e2e8f0', // 0: text
      '#94a3b8', // 1: dim text
      '#64748b', // 2
      '#334155', // 3
      '#1e293b', // 4: border
      '#0f172a', // 5: card surface
      '#0b1120', // 6: deep surface
      '#080d1a', // 7: background default
      '#050811', // 8
      '#020408', // 9
    ],
  },
  shadows: {
    md: '0 4px 20px rgba(0, 0, 0, 0.4)',
    xl: '0 12px 40px rgba(0, 0, 0, 0.6)',
  },
})
