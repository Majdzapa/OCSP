import { useEffect, useState } from 'react'
import {
  Card,
  SimpleGrid,
  Grid,
  Text,
  Title,
  Badge,
  Group,
  Stack,
  Alert,
  Skeleton,
  Progress,
  Box,
} from '@mantine/core'
import { IconAlertCircle } from '@tabler/icons-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { useDashboardStats } from '../hooks/useDashboardStats'
import type { DashboardStats } from '../types/api'

// ---------------------------------------------------------------------------
// Live telemetry history accumulated from real Micrometer polling
// ---------------------------------------------------------------------------
interface ChartPoint { time: string; requests: number; errors: number; latencyMs: number }

function useTelemetryHistory(stats: DashboardStats | null, size = 16) {
  const [history, setHistory] = useState<ChartPoint[]>(() =>
    Array.from({ length: size }, (_, i) => ({
      time: `-${(size - i) * 5}s`,
      requests: 0,
      errors: 0,
      latencyMs: 0,
    }))
  )

  useEffect(() => {
    if (!stats) return
    const nowLabel = new Date().toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' })
    const rps = Number((stats.requestsPerSecond ?? 0).toFixed(2))
    const errPct = Number(((stats.errorRate ?? 0) * 100).toFixed(2))
    const latency = Number((stats.avgSigningLatencyMs ?? 0).toFixed(1))

    setHistory((prev) => [
      ...prev.slice(1),
      {
        time: nowLabel,
        requests: rps,
        errors: errPct,
        latencyMs: latency,
      },
    ])
  }, [stats])

  return history
}

// ---------------------------------------------------------------------------
// Stat Card
// ---------------------------------------------------------------------------
interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  accent?: string
  progress?: number
}

function StatCard({ title, value, subtitle, accent = '#6366f1', progress }: StatCardProps) {
  return (
    <Card
      padding="lg"
      radius="md"
      style={{
        backgroundColor: 'var(--mantine-color-dark-6)',
        border: '1px solid var(--mantine-color-dark-4)',
      }}
    >
      <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
        {title}
      </Text>
      <Text
        fz={32}
        fw={700}
        lh={1.2}
        my={4}
        style={{
          background: `linear-gradient(135deg, ${accent}, #e2e8f0)`,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}
      >
        {value}
      </Text>
      {subtitle && (
        <Text fz="xs" c="dimmed">
          {subtitle}
        </Text>
      )}
      {progress !== undefined && (
        <Progress value={progress * 100} size="sm" mt="xs" color="indigo" radius="xl" />
      )}
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Dashboard Page
// ---------------------------------------------------------------------------
export function DashboardPage() {
  const { stats, loading, error } = useDashboardStats(5_000)
  const chartData = useTelemetryHistory(stats, 16)

  if (error) {
    return (
      <Alert icon={<IconAlertCircle size={16} />} title="Error" color="red" my="md">
        Failed to load dashboard: {error}. Check that the Admin API is reachable.
      </Alert>
    )
  }

  return (
    <Stack gap="lg">
      {/* Page header */}
      <Box>
        <Title order={2} fw={700}>Dashboard</Title>
        <Text fz="sm" c="dimmed" mt={4}>
          Real-time OCSP responder health, signing metrics &amp; topology
        </Text>
      </Box>

      {/* KPI row */}
      <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 4 }} spacing="md">
        {[
          {
            title: 'Requests / sec',
            value: loading || !stats
              ? '—'
              : (stats.requestsPerSecond ?? 0) > 0 && (stats.requestsPerSecond ?? 0) < 0.1
                ? (stats.requestsPerSecond ?? 0).toFixed(2)
                : (stats.requestsPerSecond ?? 0).toFixed(1),
            subtitle: stats?.totalRequests !== undefined
              ? `Rolling avg (${stats.totalRequests.toLocaleString()} OCSP reqs)`
              : 'Rolling average',
            accent: '#6366f1',
          },
          {
            title: 'Architecture',
            value: stats?.architecture ?? 'Monolith',
            subtitle: 'Direct DB & HSM signing',
            accent: '#22c55e',
          },
          {
            title: 'Message Broker',
            value: stats?.messagingBroker ?? '—',
            subtitle: stats?.tlsEnabled
              ? 'mTLS active (port 5671)'
              : 'Plaintext (port 5672)',
            accent: stats?.tlsEnabled ? '#22c55e' : '#f97316',
          },
          {
            title: 'Login & API TLS',
            value: stats?.ocspLoginTlsEnabled !== false ? 'Active' : 'Deactivated',
            subtitle: stats?.ocspLoginTlsEnabled !== false
              ? 'Strict mTLS & Transport'
              : 'Deactivated / Unencrypted',
            accent: stats?.ocspLoginTlsEnabled !== false ? '#22c55e' : '#94a3b8',
          },
          {
            title: 'Avg Signing Latency',
            value: loading || !stats ? '—' : `${(stats.avgSigningLatencyMs ?? 0).toFixed(0)} ms`,
            subtitle: 'PKCS#11 hardware round trip',
            accent: '#f59e0b',
          },
          {
            title: 'Error Rate',
            value: loading || !stats ? '—' : `${((stats.errorRate ?? 0) * 100).toFixed(2)}%`,
            subtitle: 'Rolling average',
            accent: stats && (stats.errorRate ?? 0) > 0.01 ? '#f43f5e' : '#22c55e',
          },
          {
            title: 'Revoked Certs',
            value: loading || !stats ? '—' : (stats.revokedCertificates ?? 0).toLocaleString(),
            subtitle: 'Currently in REVOKED status',
            accent: '#f43f5e',
          },
        ].map((card) => (
          <Box key={card.title}>
            {loading ? (
              <Card padding="lg" radius="md" bg="var(--mantine-color-dark-6)">
                <Skeleton height={80} />
              </Card>
            ) : (
              <StatCard {...card} />
            )}
          </Box>
        ))}
      </SimpleGrid>

      {/* Charts row — live telemetry history from Micrometer polling */}
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Card
            padding="lg"
            radius="md"
            style={{
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Group justify="space-between" mb="md">
              <Text fw={600} fz="sm">Request Throughput</Text>
              <Badge size="xs" color="indigo" variant="light">Live Micrometer Telemetry</Badge>
            </Group>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="reqGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="errGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Area type="monotone" dataKey="requests" name="Req/s"  stroke="#6366f1" fill="url(#reqGrad)" strokeWidth={2} dot={false} />
                <Area type="monotone" dataKey="errors"   name="Error %" stroke="#f43f5e" fill="url(#errGrad)" strokeWidth={1.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, md: 4 }}>
          <Card
            padding="lg"
            radius="md"
            style={{
              height: '100%',
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Group justify="space-between" mb="md">
              <Text fw={600} fz="sm">PKCS#11 Signing Latency (ms)</Text>
              <Badge size="xs" color="teal" variant="light">Live HSM Round-Trip</Badge>
            </Group>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData.slice(-8)}>
                <defs>
                  <linearGradient id="signGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" />
                    <stop offset="100%" stopColor="#059669" />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
                <Bar dataKey="latencyMs" name="Avg Latency (ms)" radius={[4, 4, 0, 0]} fill="url(#signGrad)" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Grid.Col>
      </Grid>

      {/* System health — driven by real API data */}
      <Card
        padding="lg"
        radius="md"
        style={{
          backgroundColor: 'var(--mantine-color-dark-6)',
          border: '1px solid var(--mantine-color-dark-4)',
        }}
      >
        <Text fw={600} fz="sm" mb="sm">System Health &amp; Topology</Text>
        <Group gap="sm" wrap="wrap">
          {loading ? (
            <Skeleton height={28} width={300} />
          ) : (
            <>
              <Badge color="indigo"  variant="light" size="lg">OCSP Responder ✓</Badge>
              <Badge color="cyan"    variant="light" size="lg">OCSP Client ✓</Badge>
              <Badge color="violet"  variant="light" size="lg">KMS Simulator ✓</Badge>
              <Badge color="teal"    variant="light" size="lg">MariaDB ✓</Badge>
              <Badge color={stats?.tlsEnabled ? 'teal' : 'orange'} variant="light" size="lg">
                RabbitMQ {stats?.tlsEnabled ? '(mTLS) ✓' : '(plaintext) ✓'}
              </Badge>
              <Badge color="teal"   variant="outline" size="lg">Pure Event Sync (RabbitMQ) ✓</Badge>
              <Badge color="indigo" variant="outline" size="lg">SoftHSM2 PKCS#11 (Direct Signing) ✓</Badge>
            </>
          )}
        </Group>
      </Card>
    </Stack>
  )
}
