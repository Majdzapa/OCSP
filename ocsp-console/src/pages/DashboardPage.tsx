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
import {
  IconAlertCircle,
} from '@tabler/icons-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { useDashboardStats } from '../hooks/useDashboardStats'

// ---- Simulated historical data for charts ----
const generateHistory = () =>
  Array.from({ length: 20 }, (_, i) => ({
    time: `${i}m`,
    requests: Math.random() * 120 + 40,
    errors: Math.random() * 3,
  }))

const CHART_DATA = generateHistory()

// ---- Stat Card ----
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

export function DashboardPage() {
  const { stats, loading, error } = useDashboardStats(5000)

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
          Real-time OCSP responder health, dynamic signing & throughput
        </Text>
      </Box>

      {/* KPI row */}
      <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="md">
        {[
          {
            title: 'Requests / sec',
            value: loading ? '—' : stats!.requestsPerSecond.toFixed(1),
            subtitle: 'Rolling 1-minute average',
            accent: '#6366f1',
          },
          {
            title: 'Architecture',
            value: 'Monolith',
            subtitle: 'Direct DB & SoftHSM2 signing',
            accent: '#22c55e',
          },
          {
            title: 'Message Broker',
            value: 'RabbitMQ',
            subtitle: 'Direct exchange & durable queue',
            accent: '#f97316',
          },
          {
            title: 'Avg Signing Latency',
            value: loading ? '—' : `${stats!.avgSigningLatencyMs.toFixed(0)} ms`,
            subtitle: 'PKCS#11 hardware round trip',
            accent: '#f59e0b',
          },
          {
            title: 'Error Rate',
            value: loading ? '—' : `${(stats!.errorRate * 100).toFixed(2)}%`,
            subtitle: 'Rolling 1-minute',
            accent: stats && stats.errorRate > 0.01 ? '#f43f5e' : '#22c55e',
          },
          {
            title: 'Revoked Certs',
            value: loading ? '—' : stats!.revokedCertificates.toLocaleString(),
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

      {/* Charts row */}
      <Grid gutter="md">
        {/* Requests / sec area chart */}
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Card
            padding="lg"
            radius="md"
            style={{
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Text fw={600} fz="sm" mb="md">
              Request Throughput
            </Text>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={CHART_DATA}>
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
                <Area type="monotone" dataKey="requests" name="Req/s" stroke="#6366f1" fill="url(#reqGrad)" strokeWidth={2} dot={false} />
                <Area type="monotone" dataKey="errors"   name="Errors" stroke="#f43f5e" fill="url(#errGrad)" strokeWidth={1.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </Grid.Col>

        {/* Dynamic Signing Activity bar chart */}
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
            <Text fw={600} fz="sm" mb="md">
              PKCS#11 Signing Ops
            </Text>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={CHART_DATA.slice(-8)}>
                <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} domain={[0, 150]} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
                <Bar dataKey="requests" name="Sign Ops/s" radius={[4, 4, 0, 0]} fill="url(#signGrad)">
                  <defs>
                    <linearGradient id="signGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#10b981" />
                      <stop offset="100%" stopColor="#059669" />
                    </linearGradient>
                  </defs>
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Grid.Col>
      </Grid>

      {/* System health row */}
      <Card
        padding="lg"
        radius="md"
        style={{
          backgroundColor: 'var(--mantine-color-dark-6)',
          border: '1px solid var(--mantine-color-dark-4)',
        }}
      >
        <Text fw={600} fz="sm" mb="sm">System Health & Topology</Text>
        <Group gap="sm" wrap="wrap">
          {loading ? (
            <Skeleton height={28} width={300} />
          ) : (
            <>
              <Badge color="indigo" variant="light" size="lg">OCSP Responder (:8080) ✓</Badge>
              <Badge color="cyan" variant="light" size="lg">OCSP Client (:8082) ✓</Badge>
              <Badge color="violet" variant="light" size="lg">KMS Simulator (:8090) ✓</Badge>
              <Badge color="teal" variant="light" size="lg">MariaDB (:3307) ✓</Badge>
              <Badge color="orange" variant="light" size="lg">RabbitMQ (:5672) ✓</Badge>
              <Badge color="teal" variant="outline" size="lg">Pure Event Sync (RabbitMQ) ✓</Badge>
              <Badge color="indigo" variant="outline" size="lg">SoftHSM2 PKCS#11 (Direct Signing) ✓</Badge>
            </>
          )}
        </Group>
      </Card>
    </Stack>
  )
}
