import { Routes, Route, Navigate, NavLink } from 'react-router-dom'
import {
  Box, Drawer, List, ListItem, ListItemButton, ListItemIcon,
  ListItemText, Toolbar, Typography, Divider, Tooltip,
} from '@mui/material'
import {
  DashboardOutlined,
  GppBadOutlined,
  ReceiptLongOutlined,
  VerifiedUserOutlined,
  ManageSearchOutlined,
  KeyOutlined,
  Circle,
} from '@mui/icons-material'
import { DashboardPage }  from './pages/DashboardPage'
import { RevocationFeed } from './pages/RevocationFeed'
import { SigningCertPage } from './pages/SigningCertPage'
import { CertCheckerPage } from './pages/CertCheckerPage'
import { KmsCertificatesPage } from './pages/KmsCertificatesPage'
import { useDashboardStats } from './hooks/useDashboardStats'

const DRAWER_WIDTH = 240

const navItems = [
  { label: 'Dashboard',       path: '/dashboard',        icon: <DashboardOutlined /> },
  { label: 'KMS Inventory',   path: '/kms-certificates', icon: <KeyOutlined /> },
  { label: 'Revocations',     path: '/revocations',      icon: <GppBadOutlined /> },
  { label: 'Signing Cert',    path: '/signing-cert',     icon: <VerifiedUserOutlined /> },
  { label: 'Cert Checker',    path: '/cert-checker',     icon: <ManageSearchOutlined /> },
  { label: 'Audit Log',       path: '/audit',            icon: <ReceiptLongOutlined /> },
]

export default function App() {
  const { stats } = useDashboardStats(10_000)

  return (
    <Box sx={{ display: 'flex', height: '100vh' }}>

      {/* ---- Sidebar ---- */}
      <Drawer
        variant="permanent"
        sx={{
          width: DRAWER_WIDTH,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: DRAWER_WIDTH,
            boxSizing: 'border-box',
            background: 'linear-gradient(180deg, #0d1424 0%, #090b14 100%)',
            borderRight: '1px solid rgba(255,255,255,0.06)',
          },
        }}
      >
        {/* Logo area */}
        <Toolbar sx={{ px: 2, py: 2.5, flexDirection: 'column', alignItems: 'flex-start', gap: 0.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box sx={{
              width: 32, height: 32, borderRadius: '8px',
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 4px 14px rgba(99,102,241,0.4)',
              fontSize: '14px', fontWeight: 700, color: '#fff',
            }}>
              🔐
            </Box>
            <Box>
              <Typography variant="body1" fontWeight={700} sx={{ lineHeight: 1.2, color: '#e2e8f0' }}>
                OCSP Console
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748b', fontSize: '0.65rem' }}>
                Incert Private CA
              </Typography>
            </Box>
          </Box>
        </Toolbar>

        <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />

        {/* Live status indicator */}
        <Box sx={{ px: 2, py: 1.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Circle sx={{
              fontSize: 8,
              color: '#22c55e',
              animation: 'pulse 2s infinite',
              '@keyframes pulse': {
                '0%': { opacity: 1 },
                '50%': { opacity: 0.4 },
                '100%': { opacity: 1 },
              }
            }} />
            <Typography variant="caption" sx={{ color: '#64748b', fontSize: '0.68rem' }}>
              LIVE — {stats ? `${stats.requestsPerSecond.toFixed(1)} req/s` : 'Connecting...'}
            </Typography>
          </Box>
        </Box>

        {/* Nav items */}
        <List sx={{ px: 1, flex: 1 }}>
          {navItems.map((item) => (
            <ListItem key={item.path} disablePadding sx={{ mb: 0.5 }}>
              <ListItemButton
                component={NavLink}
                to={item.path}
                sx={{
                  borderRadius: '10px',
                  px: 1.5,
                  py: 1,
                  color: '#64748b',
                  '&.active': {
                    background: 'linear-gradient(135deg, rgba(99,102,241,0.18), rgba(139,92,246,0.12))',
                    color: '#a5b4fc',
                    boxShadow: 'inset 0 0 0 1px rgba(99,102,241,0.2)',
                  },
                  '&:hover': {
                    background: 'rgba(99,102,241,0.08)',
                    color: '#c7d2fe',
                  },
                  transition: 'all 0.15s ease',
                }}
              >
                <ListItemIcon sx={{ color: 'inherit', minWidth: 36, '& svg': { fontSize: 18 } }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{ fontSize: '0.85rem', fontWeight: 500 }}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>

        {/* Signing cert expiry badge */}
        <Box sx={{ p: 2 }}>
          {stats && (
            <Tooltip title="Days until OCSP signing cert expires">
              <Box sx={{
                background: stats.ocspSigningCertDaysRemaining <= 7
                  ? 'rgba(244,63,94,0.12)'
                  : 'rgba(99,102,241,0.08)',
                border: `1px solid ${stats.ocspSigningCertDaysRemaining <= 7 ? 'rgba(244,63,94,0.25)' : 'rgba(99,102,241,0.2)'}`,
                borderRadius: '10px',
                p: 1.5,
              }}>
                <Typography variant="caption" sx={{ color: '#64748b', display: 'block', mb: 0.5 }}>
                  Signing cert expires in
                </Typography>
                <Typography variant="body2" fontWeight={700}
                  sx={{ color: stats.ocspSigningCertDaysRemaining <= 7 ? '#f43f5e' : '#a5b4fc' }}>
                  {stats.ocspSigningCertDaysRemaining} days
                </Typography>
              </Box>
            </Tooltip>
          )}
        </Box>
      </Drawer>

      {/* ---- Main content ---- */}
      <Box component="main" sx={{ flex: 1, overflow: 'auto', p: 3 }}>
        <Routes>
          <Route path="/"                 element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"        element={<DashboardPage />} />
          <Route path="/kms-certificates" element={<KmsCertificatesPage />} />
          <Route path="/revocations"      element={<RevocationFeed />} />
          <Route path="/signing-cert"     element={<SigningCertPage />} />
          <Route path="/cert-checker"     element={<CertCheckerPage />} />
          <Route path="/audit"            element={<RevocationFeed />} />
        </Routes>
      </Box>
    </Box>
  )
}
