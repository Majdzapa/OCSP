import { Routes, Route, Navigate, NavLink as RouterNavLink, useLocation } from 'react-router-dom';
import { AppShell, Box, Group, Stack, Text, ThemeIcon, Tooltip, Button, Badge, Avatar, Divider, NavLink as MantineNavLink, ScrollArea, Burger, Menu, UnstyledButton, } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { IconDashboard, IconShieldX, IconCertificate, IconSearch, IconCircleFilled, IconLogout, IconExternalLink, IconInbox, IconBook, IconClock, IconUsers, IconShieldCheck, IconCpu, IconApps, IconChevronRight, IconShieldLock, IconApi, IconKey, } from '@tabler/icons-react';
import { DashboardPage } from './pages/DashboardPage';
import { RevocationFeed } from './pages/RevocationFeed';
import { SigningCertificatesPage } from './pages/SigningCertificatesPage';
import { SigningCertValidityPage } from './pages/SigningCertValidityPage';
import { CertCheckerPage } from './pages/CertCheckerPage';
import { InboxAuditPage } from './pages/InboxAuditPage';
import { UserManagementPage } from './pages/UserManagementPage';
import { TrustedCasPage } from './pages/TrustedCasPage';
import { CryptoDevicesPage } from './pages/CryptoDevicesPage';
import { LoginPage } from './pages/LoginPage';
import { ProtectedRoute } from './components/ProtectedRoute';
import { AuthProvider, useAuth } from './context/AuthContext';
import { useDashboardStats } from './hooks/useDashboardStats';

// Portal links driven by build-time env vars; safe defaults for local dev only.
const PORTAL_LINKS = {
    docsHome: import.meta.env.VITE_PORTAL_DOCS ?? '/docs/ocsp/5.0/index.html',
    hsmGuide: import.meta.env.VITE_PORTAL_HSM_GUIDE ?? '/docs/ocsp/5.0/hsm-operations-guide.html',
    rabbitMq: import.meta.env.VITE_PORTAL_RABBITMQ ?? 'http://localhost:15672',
    responderSwagger: import.meta.env.VITE_PORTAL_RESPONDER_SWAGGER ?? 'http://localhost:8080/swagger-ui/index.html',
};

const NAV_SECTIONS = [
    {
        title: 'Monitoring',
        items: [
            { label: 'Dashboard', path: '/dashboard', icon: IconDashboard },
            { label: 'Revocation Feed', path: '/revocations', icon: IconShieldX },
            { label: 'Responder Inbox', path: '/inbox', icon: IconInbox },
        ],
    },
    {
        title: 'HSM & Signing',
        items: [
            { label: 'HSM Devices & Slots', path: '/hsm-devices', icon: IconCpu },
            { label: 'Signing Certificates', path: '/signing-cert', aliases: ['/signing-certificates'], icon: IconCertificate },
            { label: 'Cert Validity', path: '/signing-validity', icon: IconClock, showExpiryBadge: true },
        ],
    },
    {
        title: 'Verification & Trust',
        items: [
            { label: 'Cert Checker', path: '/cert-checker', icon: IconSearch },
            { label: 'Trusted CAs', path: '/trusted-cas', icon: IconShieldCheck },
        ],
    },
    {
        title: 'Administration',
        adminOnly: true,
        items: [
            { label: 'User Management', path: '/users', icon: IconUsers, adminOnly: true },
        ],
    },
];

function MainLayout() {
    const { user, logout } = useAuth();
    const { stats } = useDashboardStats(10_000);
    const location = useLocation();
    const [mobileOpened, { toggle: toggleMobile, close: closeMobile }] = useDisclosure(false);

    const roleNames = (user?.roles ?? []).map((r) => typeof r === 'string' ? r : (r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');
    const roleLabel = isAdmin ? 'ADMIN' : (roleNames[0]?.replace(/^ROLE_/, '') || 'USER');
    const daysRemaining = stats?.ocspSigningCertDaysRemaining;
    const expiryCritical = daysRemaining != null && daysRemaining <= 7;

    const isItemActive = (item) =>
        location.pathname === item.path || Boolean(item.aliases?.includes(location.pathname));

    return (
        <AppShell
            header={{ height: { base: 56, sm: 0 } }}
            navbar={{
                width: 268,
                breakpoint: 'sm',
                collapsed: { mobile: !mobileOpened },
            }}
            padding="md"
            styles={{
                header: {
                    backgroundColor: 'var(--mantine-color-dark-6)',
                    borderBottom: '1px solid var(--mantine-color-dark-4)',
                },
                main: {
                    backgroundColor: 'var(--mantine-color-dark-7)',
                    minHeight: '100vh',
                    color: 'var(--mantine-color-dark-0)',
                },
                navbar: {
                    backgroundColor: 'var(--mantine-color-dark-6)',
                    borderRight: '1px solid var(--mantine-color-dark-4)',
                },
            }}
        >
            {/* Compact Mobile Top Bar */}
            <AppShell.Header hiddenFrom="sm" px="md">
                <Group h="100%" justify="space-between">
                    <Group gap="sm">
                        <Burger
                            opened={mobileOpened}
                            onClick={toggleMobile}
                            aria-label="Toggle navigation"
                            size="sm"
                        />
                        <ThemeIcon size={28} radius="md" variant="gradient" gradient={{ from: 'indigo', to: 'violet' }}>
                            <IconShieldLock size={16} />
                        </ThemeIcon>
                        <Text fw={700} fz="sm" c="white">OCSP Console</Text>
                    </Group>
                    <Group gap={6} px="xs" py={3} bg="var(--mantine-color-dark-5)" style={{ borderRadius: 6 }}>
                        <IconCircleFilled size={8} color="var(--mantine-color-teal-5)" />
                        <Text fz="11px" c="dimmed">
                            {stats ? `${(stats.requestsPerSecond ?? 0).toFixed(1)} req/s` : 'Connecting...'}
                        </Text>
                    </Group>
                </Group>
            </AppShell.Header>

            {/* Structured Mantine AppShell Navbar */}
            <AppShell.Navbar p="md">
                {/* 1. Brand & Live Status */}
                <AppShell.Section>
                    <Group gap="sm" mb="sm">
                        <ThemeIcon size={36} radius="md" variant="gradient" gradient={{ from: 'indigo', to: 'violet' }}>
                            <IconShieldLock size={20} />
                        </ThemeIcon>
                        <Box>
                            <Text fw={700} fz="sm" lh={1.2} c="white">
                                OCSP Console
                            </Text>
                            <Text fz="xs" c="dimmed">
                                Incert Private CA
                            </Text>
                        </Box>
                    </Group>

                    <Group
                        justify="space-between"
                        px="xs"
                        py={6}
                        bg="var(--mantine-color-dark-5)"
                        style={{
                            borderRadius: 8,
                            border: '1px solid var(--mantine-color-dark-4)',
                        }}
                    >
                        <Group gap="xs">
                            <IconCircleFilled size={8} color="var(--mantine-color-teal-5)" />
                            <Text fz="xs" fw={600} c="teal.3">LIVE</Text>
                        </Group>
                        <Text fz="xs" c="dimmed">
                            {stats ? `${(stats.requestsPerSecond ?? 0).toFixed(1)} req/s` : 'Connecting...'}
                        </Text>
                    </Group>
                </AppShell.Section>

                {/* 2. Scrollable Primary Navigation */}
                <AppShell.Section grow component={ScrollArea} my="sm" mx="-xs" px="xs" type="auto">
                    <nav aria-label="Primary">
                        <Stack gap="md">
                            {NAV_SECTIONS
                                .filter((section) => !section.adminOnly || isAdmin)
                                .map((section) => {
                                    const visibleItems = section.items.filter((item) => !item.adminOnly || isAdmin);
                                    if (visibleItems.length === 0) return null;
                                    return (
                                        <Box key={section.title}>
                                            <Text
                                                fz="11px"
                                                fw={700}
                                                c="dimmed"
                                                tt="uppercase"
                                                px="xs"
                                                mb={6}
                                                style={{ letterSpacing: '0.06em' }}
                                            >
                                                {section.title}
                                            </Text>
                                            <Stack gap={3}>
                                                {visibleItems.map((item) => {
                                                    const Icon = item.icon;
                                                    const active = isItemActive(item);
                                                    return (
                                                        <MantineNavLink
                                                            key={item.path}
                                                            component={RouterNavLink}
                                                            to={item.path}
                                                            active={active}
                                                            onClick={closeMobile}
                                                            label={item.label}
                                                            leftSection={<Icon size={17} stroke={active ? 2.1 : 1.7} />}
                                                            rightSection={
                                                                item.showExpiryBadge && expiryCritical ? (
                                                                    <Badge size="xs" color="red" variant="filled">
                                                                        {daysRemaining}d
                                                                    </Badge>
                                                                ) : null
                                                            }
                                                            styles={{
                                                                root: {
                                                                    borderRadius: 8,
                                                                    paddingInline: 10,
                                                                    paddingBlock: 8,
                                                                    fontSize: '0.86rem',
                                                                    fontWeight: active ? 600 : 500,
                                                                    borderLeft: active
                                                                        ? '3px solid var(--mantine-color-indigo-4)'
                                                                        : '3px solid transparent',
                                                                    backgroundColor: active
                                                                        ? 'rgba(99, 102, 241, 0.16)'
                                                                        : 'transparent',
                                                                    color: active
                                                                        ? '#ffffff'
                                                                        : 'var(--mantine-color-dark-1)',
                                                                },
                                                                section: {
                                                                    color: active
                                                                        ? 'var(--mantine-color-indigo-3)'
                                                                        : 'var(--mantine-color-dark-2)',
                                                                },
                                                            }}
                                                        />
                                                    );
                                                })}
                                            </Stack>
                                        </Box>
                                    );
                                })}
                        </Stack>
                    </nav>
                </AppShell.Section>

                {/* 3. Compact Footer: Signing Expiry, Portals Menu, User Profile */}
                <AppShell.Section>
                    <Stack gap="xs">
                        {stats && (
                            <Tooltip label="Days until active OCSP signing certificate expires">
                                <Group
                                    justify="space-between"
                                    px="xs"
                                    py={6}
                                    style={{
                                        borderRadius: 8,
                                        backgroundColor: expiryCritical
                                            ? 'rgba(244,63,94,0.12)'
                                            : 'rgba(99,102,241,0.08)',
                                        border: `1px solid ${expiryCritical
                                            ? 'rgba(244,63,94,0.35)'
                                            : 'rgba(99,102,241,0.22)'}`,
                                    }}
                                >
                                    <Text fz="xs" c="dimmed">Signing cert expiry</Text>
                                    <Text fw={700} fz="xs" c={expiryCritical ? 'red.4' : 'indigo.3'}>
                                        {daysRemaining} days
                                    </Text>
                                </Group>
                            </Tooltip>
                        )}

                        <Menu position="right-end" withArrow shadow="md" width={250} trigger="click">
                            <Menu.Target>
                                <UnstyledButton
                                    px="xs"
                                    py={8}
                                    style={{
                                        width: '100%',
                                        borderRadius: 8,
                                        border: '1px solid var(--mantine-color-dark-4)',
                                        backgroundColor: 'var(--mantine-color-dark-5)',
                                        color: 'var(--mantine-color-dark-0)',
                                    }}
                                >
                                    <Group justify="space-between">
                                        <Group gap={8}>
                                            <IconApps size={16} color="var(--mantine-color-indigo-3)" />
                                            <Text fz="xs" fw={600}>Portals &amp; API Docs</Text>
                                        </Group>
                                        <IconChevronRight size={14} color="var(--mantine-color-dark-2)" />
                                    </Group>
                                </UnstyledButton>
                            </Menu.Target>

                            <Menu.Dropdown>
                                <Menu.Label>Documentation</Menu.Label>
                                <Menu.Item
                                    component="a"
                                    href={PORTAL_LINKS.docsHome}
                                    target="_blank"
                                    rel="noreferrer"
                                    leftSection={<IconBook size={15} />}
                                    rightSection={<IconExternalLink size={13} />}
                                >
                                    Antora Docs
                                </Menu.Item>
                                <Menu.Item
                                    component="a"
                                    href={PORTAL_LINKS.hsmGuide}
                                    target="_blank"
                                    rel="noreferrer"
                                    leftSection={<IconKey size={15} />}
                                    rightSection={<IconExternalLink size={13} />}
                                >
                                    HSM Operations Guide
                                </Menu.Item>

                                <Menu.Divider />
                                <Menu.Label>Operations &amp; OpenAPI</Menu.Label>
                                <Menu.Item
                                    component="a"
                                    href={PORTAL_LINKS.rabbitMq}
                                    target="_blank"
                                    rel="noreferrer"
                                    leftSection={<IconApps size={15} />}
                                    rightSection={<IconExternalLink size={13} />}
                                >
                                    RabbitMQ Console (15672)
                                </Menu.Item>
                                <Menu.Item
                                    component="a"
                                    href={PORTAL_LINKS.responderSwagger}
                                    target="_blank"
                                    rel="noreferrer"
                                    leftSection={<IconApi size={15} />}
                                    rightSection={<IconExternalLink size={13} />}
                                >
                                    OCSP OpenAPI / Swagger (8080)
                                </Menu.Item>
                            </Menu.Dropdown>
                        </Menu>

                        <Divider color="var(--mantine-color-dark-4)" />

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
                                        {(user?.username ?? '?')[0].toUpperCase()}
                                    </Avatar>
                                    <Box>
                                        <Text fz="xs" fw={600} lh={1.1} c="white">
                                            {user?.username ?? '—'}
                                        </Text>
                                        <Text fz="10px" c="dimmed">
                                            {user?.authMode ?? 'Basic'}
                                        </Text>
                                    </Box>
                                </Group>
                                <Badge size="xs" color="indigo" variant="light">
                                    {roleLabel}
                                </Badge>
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
                </AppShell.Section>
            </AppShell.Navbar>

            <AppShell.Main>
                <Routes>
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    <Route path="/dashboard" element={<DashboardPage />} />
                    <Route path="/inbox" element={<InboxAuditPage />} />
                    <Route path="/revocations" element={<RevocationFeed />} />
                    <Route path="/signing-cert" element={<SigningCertificatesPage />} />
                    <Route path="/signing-certificates" element={<SigningCertificatesPage />} />
                    <Route path="/hsm-devices" element={<CryptoDevicesPage />} />
                    <Route path="/signing-validity" element={<SigningCertValidityPage />} />
                    <Route path="/cert-checker" element={<CertCheckerPage />} />
                    <Route path="/trusted-cas" element={<TrustedCasPage />} />
                    <Route path="/users" element={isAdmin ? <UserManagementPage /> : <Navigate to="/dashboard" replace />} />
                    <Route path="/audit" element={<RevocationFeed />} />
                </Routes>
            </AppShell.Main>
        </AppShell>
    );
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
    );
}
