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
} from '@mantine/core'
import {
  IconShieldCheck,
  IconAlertTriangle,
  IconRefresh,
} from '@tabler/icons-react'
import { useDashboardStats } from '../hooks/useDashboardStats'

export function SigningCertPage() {
  const { stats, loading } = useDashboardStats(30_000)

  const days = stats?.ocspSigningCertDaysRemaining ?? null
  const isWarning = days !== null && days <= 14
  const isCritical = days !== null && days <= 7

  return (
    <Box className="page-enter">
      <Box mb="lg">
        <Title order={3} fw={700}>
          OCSP Signing Certificate
        </Title>
        <Text fz="sm" c="dimmed" mt={4}>
          Delegated signing certificate lifecycle — issued by Incert, HSM-backed
        </Text>
      </Box>

      {isCritical && (
        <Alert
          color="red"
          icon={<IconAlertTriangle size={18} />}
          title="CRITICAL EXPIRATION"
          mb="lg"
        >
          The OCSP signing certificate expires in {days} day
          {days !== 1 ? 's' : ''}. Immediate rotation required to avoid responder
          outage.
        </Alert>
      )}

      {isWarning && !isCritical && (
        <Alert
          color="yellow"
          icon={<IconAlertTriangle size={18} />}
          title="EXPIRING SOON"
          mb="lg"
        >
          The OCSP signing certificate expires in {days} days. Plan rotation
          now.
        </Alert>
      )}

      <Grid gutter="md">
        {/* Validity panel */}
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
                  <Text fw={700} fz="md">
                    Active Signing Cert
                  </Text>
                  <Badge
                    color={isCritical ? 'red' : isWarning ? 'yellow' : 'teal'}
                    variant="light"
                    size="sm"
                  >
                    {isCritical
                      ? 'CRITICAL'
                      : isWarning
                      ? 'EXPIRING SOON'
                      : 'VALID'}
                  </Badge>
                </Box>
              </Group>
            </Group>

            {loading ? (
              <Stack gap="sm">
                <Skeleton height={20} />
                <Skeleton height={12} />
                <Skeleton height={100} />
              </Stack>
            ) : (
              <Box>
                <Group justify="space-between" mb={6}>
                  <Text fz="sm" c="dimmed">
                    Days remaining
                  </Text>
                  <Text
                    fz="sm"
                    fw={700}
                    c={isCritical ? 'red' : isWarning ? 'yellow' : 'teal'}
                  >
                    {days} days
                  </Text>
                </Group>
                <Progress
                  value={Math.min(100, ((days ?? 0) / 90) * 100)}
                  color={isCritical ? 'red' : isWarning ? 'yellow' : 'teal'}
                  size="md"
                  radius="xl"
                  mb="lg"
                />

                {/* Static metadata */}
                {[
                  { label: 'Key Algorithm', value: 'RSA-4096' },
                  { label: 'Signature Alg', value: 'SHA256withRSA' },
                  { label: 'EKU', value: 'id-kp-OCSPSigning' },
                  { label: 'nocheck ext', value: 'id-pkix-ocsp-nocheck ✓' },
                  { label: 'KMS Key Ref', value: 'ocsp-signing-key-01' },
                  { label: 'Issued by', value: 'Incert-Root-CA-01' },
                ].map(({ label, value }) => (
                  <Group
                    key={label}
                    justify="space-between"
                    py={8}
                    style={{
                      borderBottom: '1px solid var(--mantine-color-dark-4)',
                    }}
                  >
                    <Text fz="sm" c="dimmed">
                      {label}
                    </Text>
                    <Text
                      fz="xs"
                      ff="'JetBrains Mono', monospace"
                      c="indigo.3"
                    >
                      {value}
                    </Text>
                  </Group>
                ))}
              </Box>
            )}
          </Card>
        </Grid.Col>

        {/* Auto-rotation info */}
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
              <Text fw={700} fz="md">
                Auto-Rotation Policy
              </Text>
            </Group>

            <Stack gap={0}>
              {[
                { label: 'Rotation trigger', value: 'T-14 days before expiry' },
                { label: 'Rotation method', value: 'KMS auto-issues new cert' },
                { label: 'Cert lifetime', value: '90 days' },
                { label: 'Alert at T-14 days', value: 'Prometheus alert → PagerDuty' },
                { label: 'Alert at T-7 days', value: 'Critical — page on-call' },
                { label: 'Alert at T-1 day', value: 'Critical — escalation' },
                { label: 'Private key', value: 'Stays in KMS/HSM — never exported' },
              ].map(({ label, value }) => (
                <Group
                  key={label}
                  justify="space-between"
                  py={8}
                  style={{
                    borderBottom: '1px solid var(--mantine-color-dark-4)',
                  }}
                >
                  <Text fz="sm" c="dimmed">
                    {label}
                  </Text>
                  <Text fz="sm" fw={500} ta="right" style={{ maxWidth: '60%' }}>
                    {value}
                  </Text>
                </Group>
              ))}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </Box>
  )
}
