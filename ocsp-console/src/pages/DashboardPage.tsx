import {
  Box, Grid, Card, CardContent, Typography, LinearProgress,
  Skeleton, Alert, Chip,
} from '@mui/material'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { useDashboardStats } from '../hooks/useDashboardStats'

// ---- Simulated historical data for charts (replace with real API data) ----
const generateHistory = () =>
  Array.from({ length: 20 }, (_, i) => ({
    time: `${i}m`,
    requests: Math.random() * 120 + 40,
    cacheHit: Math.random() * 30 + 60,
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
    <Card>
      <CardContent sx={{ pb: '16px !important' }}>
        <Typography variant="caption" sx={{ color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          {title}
        </Typography>
        <Typography variant="h4" sx={{
          mt: 1, mb: 0.5, fontWeight: 700,
          background: `linear-gradient(135deg, ${accent}, #e2e8f0)`,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}>
          {value}
        </Typography>
        {subtitle && (
          <Typography variant="body2" sx={{ color: '#64748b', fontSize: '0.75rem' }}>
            {subtitle}
          </Typography>
        )}
        {progress !== undefined && (
          <Box sx={{ mt: 1.5 }}>
            <LinearProgress
              variant="determinate"
              value={progress * 100}
              sx={{
                '& .MuiLinearProgress-bar': {
                  background: `linear-gradient(90deg, ${accent}, #e2e8f0)`,
                },
              }}
            />
          </Box>
        )}
      </CardContent>
    </Card>
  )
}

export function DashboardPage() {
  const { stats, loading, error } = useDashboardStats(5000)

  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        Failed to load dashboard: {error}. Check that the Admin API is reachable.
      </Alert>
    )
  }

  return (
    <Box className="page-enter">
      {/* Page header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>Dashboard</Typography>
        <Typography variant="body2" sx={{ color: '#64748b', mt: 0.5 }}>
          Real-time OCSP responder health & throughput
        </Typography>
      </Box>

      {/* KPI row */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {[
          {
            title: 'Requests / sec',
            value: loading ? '—' : stats!.requestsPerSecond.toFixed(1),
            subtitle: 'Rolling 1-minute average',
            accent: '#6366f1',
          },
          {
            title: 'L1 Cache Hit',
            value: loading ? '—' : `${(stats!.l1HitRatio * 100).toFixed(1)}%`,
            subtitle: 'In-JVM Caffeine cache',
            accent: '#22c55e',
            progress: loading ? undefined : stats!.l1HitRatio,
          },
          {
            title: 'L2 Cache Hit',
            value: loading ? '—' : `${(stats!.l2HitRatio * 100).toFixed(1)}%`,
            subtitle: 'Shared MariaDB cache',
            accent: '#a78bfa',
            progress: loading ? undefined : stats!.l2HitRatio,
          },
          {
            title: 'Avg Signing Latency',
            value: loading ? '—' : `${stats!.avgSigningLatencyMs.toFixed(0)} ms`,
            subtitle: 'KMS signing round trip',
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
          <Grid item xs={12} sm={6} md={4} key={card.title}>
            {loading
              ? <Card><CardContent><Skeleton variant="text" height={80} /></CardContent></Card>
              : <StatCard {...card} />
            }
          </Grid>
        ))}
      </Grid>

      {/* Charts row */}
      <Grid container spacing={2}>
        {/* Requests / sec area chart */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontSize: '0.95rem' }}>
                Request Throughput
              </Typography>
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
            </CardContent>
          </Card>
        </Grid>

        {/* Cache hit ratio bar chart */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontSize: '0.95rem' }}>
                Cache Hit Ratio
              </Typography>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={CHART_DATA.slice(-8)}>
                  <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
                  <Bar dataKey="cacheHit" name="Hit %" radius={[4, 4, 0, 0]}
                    fill="url(#cacheGrad)">
                    <defs>
                      <linearGradient id="cacheGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#8b5cf6" />
                        <stop offset="100%" stopColor="#6366f1" />
                      </linearGradient>
                    </defs>
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* System health row */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontSize: '0.95rem' }}>System Health</Typography>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                {loading ? (
                  <Skeleton width={400} />
                ) : (
                  <>
                    <Chip label="OCSP Responder ✓" color="success" size="small" />
                    <Chip label="Sync Service ✓" color="success" size="small" />
                    <Chip label="MariaDB ✓" color="success" size="small" />
                    <Chip label="Kafka ✓" color="success" size="small" />
                    <Chip
                      label={`Reconciliation ${stats?.lastReconciliationOk ? '✓ OK' : '✗ FAILED'}`}
                      color={stats?.lastReconciliationOk ? 'success' : 'error'}
                      size="small"
                    />
                    <Chip
                      label={`L2 Cache: ${stats?.activeCacheEntries.toLocaleString()} entries`}
                      color="info"
                      size="small"
                    />
                  </>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  )
}
