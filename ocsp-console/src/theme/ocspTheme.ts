import { createTheme } from '@mui/material/styles'

const PRIMARY   = '#6366f1'  // Indigo
const SECONDARY = '#8b5cf6'  // Violet
const BG_PAPER  = '#0f1629'
const BG_DEFAULT = '#090b14'

export const ocspTheme = createTheme({
  palette: {
    mode: 'dark',
    primary:   { main: PRIMARY,   light: '#818cf8', dark: '#4f46e5' },
    secondary: { main: SECONDARY, light: '#a78bfa', dark: '#7c3aed' },
    error:     { main: '#f43f5e' },
    warning:   { main: '#f59e0b' },
    success:   { main: '#22c55e' },
    background: {
      default: BG_DEFAULT,
      paper:   BG_PAPER,
    },
    text: {
      primary:   '#e2e8f0',
      secondary: '#94a3b8',
    },
    divider: 'rgba(255, 255, 255, 0.08)',
  },

  typography: {
    fontFamily: "'Inter', system-ui, sans-serif",
    h4: { fontWeight: 700, letterSpacing: '-0.02em' },
    h5: { fontWeight: 600, letterSpacing: '-0.015em' },
    h6: { fontWeight: 600 },
    subtitle2: { color: '#94a3b8', fontWeight: 400 },
    body2: { color: '#94a3b8' },
    caption: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem' },
  },

  shape: { borderRadius: 12 },

  components: {
    MuiCssBaseline: {
      styleOverrides: `
        * { box-sizing: border-box; }
      `,
    },
    MuiCard: {
      styleOverrides: {
        root: {
          background: 'rgba(15, 22, 41, 0.7)',
          backdropFilter: 'blur(20px)',
          border: '1px solid rgba(255,255,255,0.07)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          transition: 'transform 0.2s ease, box-shadow 0.2s ease',
          '&:hover': {
            boxShadow: '0 12px 40px rgba(0,0,0,0.5)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { fontWeight: 600, fontSize: '0.72rem', letterSpacing: '0.05em' },
      },
    },
    MuiTableHead: {
      styleOverrides: {
        root: {
          '& .MuiTableCell-head': {
            background: 'rgba(99,102,241,0.08)',
            fontWeight: 600,
            color: '#94a3b8',
            textTransform: 'uppercase',
            fontSize: '0.7rem',
            letterSpacing: '0.08em',
          },
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { borderColor: 'rgba(255,255,255,0.05)' },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          borderRadius: 8,
        },
        containedPrimary: {
          background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
          boxShadow: '0 4px 15px rgba(99,102,241,0.35)',
          '&:hover': {
            background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
            boxShadow: '0 4px 20px rgba(99,102,241,0.5)',
          },
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: { borderRadius: 4, height: 6 },
        barColorPrimary: {
          background: 'linear-gradient(90deg, #6366f1, #8b5cf6)',
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: '#1e293b',
          border: '1px solid rgba(255,255,255,0.1)',
          fontSize: '0.75rem',
        },
      },
    },
  },
})
