import { Routes, Route, Navigate, NavLink } from 'react-router-dom'
import {
  AppShell,
  Box,
  Group,
  Stack,
  Text,
  ThemeIcon,
  Tooltip,
  Button,
  Badge,
  Avatar,
  Divider,
} from '@mantine/core'
import {
  IconDashboard,
  IconKey,
  IconShieldX,
  IconCertificate,
  IconSearch,
  IconReceipt,
  IconCircleFilled,
  IconLogout,
  IconExternalLink,
  IconInbox,
} from '@tabler/icons-react'
import { DashboardPage }  from './pages/DashboardPage'
import { RevocationFeed } from './pages/RevocationFeed'
import { SigningCertPage } from './pages/SigningCertPage'
import { CertCheckerPage } from './pages/CertCheckerPage'
import { KmsCertificatesPage } from './pages/KmsCertificatesPage'
import { InboxAuditPage } from './pages/InboxAuditPage'
import { LoginPage } from './pages/LoginPage'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AuthProvider, useAuth } from './context/AuthContext'
import { useDashboardStats } from './hooks/useDashboardStats'

const navItems = [
  { label: 'Dashboard',       path: '/dashboard',        icon: IconDashboard },
  { label: 'KMS Inventory',   path: '/kms-certificates', icon: IconKey },
  { label: 'Responder Inbox', path: '/inbox',            icon: IconInbox },
  { label: 'Revocations',     path: '/revocations',      icon: IconShieldX },
  { label: 'Signing Cert',    path: '/signing-cert',     icon: IconCertificate },
  { label: 'Cert Checker',    path: '/cert-checker',     icon: IconSearch },
  { label: 'Audit Log',       path: '/audit',            icon: IconReceipt },
]

function MainLayout() {
  const { user, logout } = useAuth()
  const { stats } = useDashboardStats(10_000)

  return (
    <AppShell
      navbar={{ width: 250, breakpoint: 'sm' }}
      padding="md"
      styles={{
        main: {
          backgroundColor: 'var(--mantine-color-dark-7)',
          minHeight: '100vh',
          color: 'var(--mantine-color-dark-0)',
        },
        navbar: {
          backgroundColor: 'var(--mantine-color-dark-6)',
          borderRight: '1px solid var(--mantine-color-dark-4)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        },
      }}
    >
      <AppShell.Navbar p="md">
        <Stack gap="sm">
          {/* Logo */}
          <Group gap="sm" mb="xs">
            <ThemeIcon size={36} radius="md" variant="gradient" gradient={{ from: 'indigo', to: 'violet' }}>
              <Text fw={700} fz="lg">🔐</Text>
            </ThemeIcon>
            <Box>
              <Text fw={700} fz="sm" lh={1.2}>
                OCSP Console
              </Text>
              <Text fz="xs" c="dimmed">
                Incert Private CA
              </Text>
            </Box>
          </Group>

          {/* Live indicator */}
          <Group gap="xs" px="xs" py={4} bg="var(--mantine-color-dark-5)" style={{ borderRadius: 8 }}>
            <IconCircleFilled size={8} color="var(--mantine-color-teal-5)" />
            <Text fz="xs" c="dimmed">
              LIVE — {stats ? `${stats.requestsPerSecond.toFixed(1)} req/s` : 'Connecting...'}
            </Text>
          </Group>

          {/* Nav Items */}
          <Stack gap={4} mt="xs">
            {navItems.map((item) => {
              const Icon = item.icon
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  style={({ isActive }) => ({
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '9px 12px',
                    borderRadius: 8,
                    textDecoration: 'none',
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    color: isActive ? 'var(--mantine-color-indigo-2)' : 'var(--mantine-color-dark-1)',
                    backgroundColor: isActive ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
                    border: isActive ? '1px solid rgba(99, 102, 241, 0.3)' : '1px solid transparent',
                    transition: 'all 150ms ease',
                  })}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </NavLink>
              )
            })}
          </Stack>

          <Box mt="xs">
            <Text fz="11px" fw={700} c="dimmed" tt="uppercase" px="xs" mb={4}>
              Direct Portals
            </Text>
            <Stack gap={2}>
              <a
                href="http://localhost:8090"
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 12px',
                  borderRadius: 6,
                  color: 'var(--mantine-color-dark-2)',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                }}
              >
                <span>KMS Portal (8090)</span>
                <IconExternalLink size={14} />
              </a>
              <a
                href="http://localhost:8082"
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 12px',
                  borderRadius: 6,
                  color: 'var(--mantine-color-dark-2)',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                }}
              >
                <span>OCSP Test Tool (8082)</span>
                <IconExternalLink size={14} />
              </a>
              <a
                href="http://localhost:15672"
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 12px',
                  borderRadius: 6,
                  color: 'var(--mantine-color-dark-2)',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                }}
              >
                <span>RabbitMQ (15672)</span>
                <IconExternalLink size={14} />
              </a>
            </Stack>
          </Box>

          <Box mt="xs">
            <Text fz="11px" fw={700} c="dimmed" tt="uppercase" px="xs" mb={4}>
              Swagger / OpenAPI
            </Text>
            <Stack gap={2}>
              <a
                href="http://localhost:8080/swagger-ui/index.html"
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 12px',
                  borderRadius: 6,
                  color: 'var(--mantine-color-indigo-3)',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                }}
              >
                <span>Responder Swagger (8080)</span>
                <IconExternalLink size={14} />
              </a>
              <a
                href="http://localhost:8082/swagger-ui/index.html"
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 12px',
                  borderRadius: 6,
                  color: 'var(--mantine-color-indigo-3)',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                }}
              >
                <span>Client Swagger (8082)</span>
                <IconExternalLink size={14} />
              </a>
              <a
                href="http://localhost:8090/swagger-ui/index.html"
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 12px',
                  borderRadius: 6,
                  color: 'var(--mantine-color-indigo-3)',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                }}
              >
                <span>KMS Swagger (8090)</span>
                <IconExternalLink size={14} />
              </a>
            </Stack>
          </Box>
        </Stack>

        {/* Footer: User profile & Signing cert expiry */}
        <Stack gap="xs">
          {stats && (
            <Tooltip label="Days until OCSP signing cert expires">
              <Box
                p="xs"
                style={{
                  borderRadius: 8,
                  backgroundColor: stats.ocspSigningCertDaysRemaining <= 7 ? 'rgba(244,63,94,0.12)' : 'rgba(99,102,241,0.08)',
                  border: `1px solid ${stats.ocspSigningCertDaysRemaining <= 7 ? 'rgba(244,63,94,0.3)' : 'rgba(99,102,241,0.2)'}`,
                }}
              >
                <Text fz="xs" c="dimmed">
                  Signing cert expires in
                </Text>
                <Text fw={700} fz="sm" c={stats.ocspSigningCertDaysRemaining <= 7 ? 'red.5' : 'indigo.3'}>
                  {stats.ocspSigningCertDaysRemaining} days
                </Text>
              </Box>
            </Tooltip>
          )}

          <Divider color="var(--mantine-color-dark-4)" />

          {/* User profile & Logout */}
          <Box
            p="xs"
            style={{
              backgroundColor: 'var(--mantine-color-dark-5)',
              borderRadius: 8,
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Group justify="space-between" mb={6}>
              <Group gap="xs">
                <Avatar size="sm" radius="xl" color="indigo">
                  {(user?.username || 'A')[0].toUpperCase()}
                </Avatar>
                <Box>
                  <Text fz="xs" fw={600} lh={1.1} c="white">
                    {user?.username || 'admin'}
                  </Text>
                  <Text fz="10px" c="dimmed">
                    {user?.apiKey ? 'API-KEY Auth' : 'Basic Auth'}
                  </Text>
                </Box>
              </Group>
              <Badge size="xs" color="indigo" variant="light">ADMIN</Badge>
            </Group>

            <Button
              variant="subtle"
              color="red"
              size="xs"
              fullWidth
              leftSection={<IconLogout size={14} />}
              onClick={logout}
              mt={4}
            >
              Sign Out
            </Button>
          </Box>
        </Stack>
      </AppShell.Navbar>

      <AppShell.Main>
        <Routes>
          <Route path="/"                 element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"        element={<DashboardPage />} />
          <Route path="/kms-certificates" element={<KmsCertificatesPage />} />
          <Route path="/inbox"            element={<InboxAuditPage />} />
          <Route path="/revocations"      element={<RevocationFeed />} />
          <Route path="/signing-cert"     element={<SigningCertPage />} />
          <Route path="/cert-checker"     element={<CertCheckerPage />} />
          <Route path="/audit"            element={<RevocationFeed />} />
        </Routes>
      </AppShell.Main>
    </AppShell>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        />
      </Routes>
    </AuthProvider>
  )
}
