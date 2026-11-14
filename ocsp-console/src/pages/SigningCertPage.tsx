import { useState, useEffect } from 'react'
import {
  Box,
  Title,
  Text,
  Card,
  Grid,
  Badge,
  Progress,
  Alert,
  Group,
  Stack,
  Skeleton,
  Button,
} from '@mantine/core'
import {
  IconShieldCheck,
  IconAlertTriangle,
  IconRefresh,
} from '@tabler/icons-react'
import { getSigningCertificates } from '../api/client'
import type { SigningCertificateDto } from '../types/api'
import { useDashboardStats } from '../hooks/useDashboardStats'

// Auto-rotation policy metadata — matches the responder's configured thresholds.
// These are display-only values that mirror what is configured on the server side.
const ROTATION_POLICY = [
  { label: 'Rotation trigger',  value: 'T-14 days before expiry' },
  { label: 'Rotation method',   value: 'Admin activates new cert via Signing Certs page' },
  { label: 'Alert at T-14',     value: 'Warning banner in console' },
  { label: 'Alert at T-7',      value: 'Critical — Prometheus alert' },
  { label: 'Alert at T-1',      value: 'Critical — escalation required' },
  { label: 'Private key',       value: 'Stays in KMS/HSM — never exported (CKA_EXTRACTABLE=FALSE)' },
] as const

export function SigningCertPage() {
  const { stats, loading: statsLoading } = useDashboardStats(30_000)
  const [activeCert, setActiveCert] = useState<SigningCertificateDto | null>(null)
  const [certLoading, setCertLoading] = useState(true)
  const [certError, setCertError] = useState<string | null>(null)

  const fetchActiveCert = async () => {
    setCertLoading(true)
    setCertError(null)
    try {
      const certs = await getSigningCertificates()
      setActiveCert(certs.find((c) => c.active) ?? null)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load signing certificate'
      setCertError(msg)
    } finally {
      setCertLoading(false)
    }
  }

  useEffect(() => {
    fetchActiveCert()
  }, [])

  const days = activeCert?.daysUntilExpiry ?? stats?.ocspSigningCertDaysRemaining ?? null
  const isWarning  = days !== null && days <= 14
  const isCritical = days !== null && days <= 7

  return (
    <Box>
      <Box mb="lg">
        <Title order={3} fw={700}>OCSP Signing Certificate</Title>
        <Text fz="sm" c="dimmed" mt={4}>
          Delegated signing certificate lifecycle — HSM-backed, never exported
        </Text>
      </Box>

      {isCritical && (
        <Alert color="red" icon={<IconAlertTriangle size={18} />} title="CRITICAL EXPIRATION" mb="lg">
          The OCSP signing certificate expires in {days} day{days !== 1 ? 's' : ''}. Immediate rotation required.
        </Alert>
      )}
      {isWarning && !isCritical && (
        <Alert color="yellow" icon={<IconAlertTriangle size={18} />} title="EXPIRING SOON" mb="lg">
          The OCSP signing certificate expires in {days} days. Plan rotation now.
        </Alert>
      )}

      <Grid gutter="md">
        {/* Active certificate details */}
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card
            p="lg"
            radius="md"
            style={{
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Group justify="space-between" mb="md">
              <Group gap="sm">
                <IconShieldCheck
                  size={28}
                  color={isCritical ? '#f43f5e' : isWarning ? '#f59e0b' : '#22c55e'}
                />
                <Box>
                  <Text fw={700} fz="md">Active Signing Cert</Text>
                  <Badge
                    color={isCritical ? 'red' : isWarning ? 'yellow' : 'teal'}
                    variant="light"
                    size="sm"
                  >
                    {isCritical ? 'CRITICAL' : isWarning ? 'EXPIRING SOON' : 'VALID'}
                  </Badge>
                </Box>
              </Group>
              <Button
                variant="subtle"
                size="xs"
                leftSection={<IconRefresh size={14} />}
                onClick={fetchActiveCert}
                loading={certLoading}
              >
                Refresh
              </Button>
            </Group>

            {certError && (
              <Alert color="red" mb="sm">{certError}</Alert>
            )}

            {certLoading || statsLoading ? (
              <Stack gap="sm">
                <Skeleton height={20} />
                <Skeleton height={12} />
                {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} height={36} />)}
              </Stack>
            ) : (
              <Box>
                <Group justify="space-between" mb={6}>
                  <Text fz="sm" c="dimmed">Days remaining</Text>
                  <Text fz="sm" fw={700} c={isCritical ? 'red' : isWarning ? 'yellow' : 'teal'}>
                    {days ?? '—'} days
                  </Text>
                </Group>
                <Progress
                  value={Math.min(100, ((days ?? 0) / 90) * 100)}
                  color={isCritical ? 'red' : isWarning ? 'yellow' : 'teal'}
                  size="md"
                  radius="xl"
                  mb="lg"
                />

                {/* Real cert metadata from API */}
                {[
                  { label: 'Alias',          value: activeCert?.alias          ?? '—' },
                  { label: 'Key Label',       value: activeCert?.keyLabel       ?? '—' },
                  { label: 'Signature Alg',   value: activeCert?.signatureAlgorithm ?? '—' },
                  { label: 'Subject DN',      value: activeCert?.subjectDn      ?? '—' },
                  { label: 'Issuer DN',       value: activeCert?.issuerDn       ?? '—' },
                  { label: 'Serial',          value: activeCert?.serialNumber   ?? '—' },
                  { label: 'Not Before',      value: activeCert?.notBefore ? new Date(activeCert.notBefore).toLocaleDateString() : '—' },
                  { label: 'Not After',       value: activeCert?.notAfter  ? new Date(activeCert.notAfter).toLocaleDateString()  : '—' },
                ].map(({ label, value }) => (
                  <Group
                    key={label}
                    justify="space-between"
                    py={8}
                    style={{ borderBottom: '1px solid var(--mantine-color-dark-4)' }}
                  >
                    <Text fz="sm" c="dimmed">{label}</Text>
                    <Text
                      fz="xs"
                      ff="'JetBrains Mono', monospace"
                      c="indigo.3"
                      style={{ maxWidth: '60%', textAlign: 'right', wordBreak: 'break-all' }}
                    >
                      {value}
                    </Text>
                  </Group>
                ))}
              </Box>
            )}
          </Card>
        </Grid.Col>

        {/* Auto-rotation policy */}
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card
            p="lg"
            radius="md"
            style={{
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Group gap="sm" mb="md">
              <IconRefresh size={26} color="#6366f1" />
              <Text fw={700} fz="md">Rotation Policy</Text>
            </Group>

            <Stack gap={0}>
              {ROTATION_POLICY.map(({ label, value }) => (
                <Group
                  key={label}
                  justify="space-between"
                  py={8}
                  style={{ borderBottom: '1px solid var(--mantine-color-dark-4)' }}
                >
                  <Text fz="sm" c="dimmed">{label}</Text>
                  <Text fz="sm" fw={500} ta="right" style={{ maxWidth: '60%' }}>{value}</Text>
                </Group>
              ))}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </Box>
  )
}
