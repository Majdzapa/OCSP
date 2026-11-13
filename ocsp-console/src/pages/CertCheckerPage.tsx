import { useState } from 'react'
import {
  Box,
  Title,
  Text,
  Card,
  Grid,
  Paper,
  TextInput,
  Textarea,
  Button,
  Badge,
  Alert,
  Collapse,
  Modal,
  Tabs,
  Switch,
  Radio,
  Group,
  Stack,
} from '@mantine/core'
import {
  IconSearch,
  IconShieldCheck,
  IconShieldX,
  IconHelp,
  IconRefresh,
  IconCopy,
  IconKey,
  IconBolt,
  IconGauge,
  IconCpu,
  IconTerminal2,
  IconAlertCircle,
  IconCheck,
} from '@tabler/icons-react'
import {
  checkCertStatus,
  requestCertRenewal,
  testOcspRequest,
} from '../api/client'
import type {
  CertStatusResponse,
  RenewRequestResponse,
  OcspTestResult,
} from '../types/api'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function StatusBadge({
  status,
}: {
  status: CertStatusResponse['status'] | string
}) {
  const map: Record<
    string,
    { label: string; color: string; icon: React.ReactElement }
  > = {
    GOOD: {
      label: 'GOOD',
      color: 'teal',
      icon: <IconShieldCheck size={14} />,
    },
    REVOKED: {
      label: 'REVOKED',
      color: 'red',
      icon: <IconShieldX size={14} />,
    },
    UNKNOWN: {
      label: 'UNKNOWN',
      color: 'yellow',
      icon: <IconHelp size={14} />,
    },
  }
  const entry = map[status] ?? {
    label: status,
    color: 'gray',
    icon: <IconHelp size={14} />,
  }

  return (
    <Badge
      leftSection={entry.icon}
      color={entry.color}
      variant="filled"
      size="lg"
      radius="sm"
    >
      {entry.label}
    </Badge>
  )
}

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string | null | undefined
  mono?: boolean
}) {
  if (value === null || value === undefined || value === '') return null
  return (
    <Group
      justify="space-between"
      align="flex-start"
      py={8}
      style={{
        borderBottom: '1px solid var(--mantine-color-dark-4)',
      }}
    >
      <Text fz="sm" c="dimmed" style={{ minWidth: 160 }}>
        {label}
      </Text>
      <Text
        fz={mono ? 'xs' : 'sm'}
        ff={mono ? "'JetBrains Mono', monospace" : 'inherit'}
        ta="right"
        style={{ wordBreak: 'break-all' }}
      >
        {value}
      </Text>
    </Group>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function CertCheckerPage() {
  const [activeTab, setActiveTab] = useState<string | null>('ocsp-tester')

  // Tab 0: Live OCSP Protocol Tester
  const [testSerial, setTestSerial] = useState(
    '00b59d41baf78afe0de1bbe7ae28c0450f'
  ) // ee-01
  const [includeNonce, setIncludeNonce] = useState(false)
  const [httpMethod, setHttpMethod] = useState<'POST' | 'GET'>('POST')
  const [testLoading, setTestLoading] = useState(false)
  const [testResult, setTestResult] = useState<OcspTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [copiedCmd, setCopiedCmd] = useState(false)

  // Tab 1: Database Status Lookup
  const [serial, setSerial] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<CertStatusResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Renewal dialog
  const [renewOpen, setRenewOpen] = useState(false)
  const [renewReason, setRenewReason] = useState(
    'REVOKED — renewal requested via admin console'
  )
  const [renewLoading, setRenewLoading] = useState(false)
  const [renewResult, setRenewResult] = useState<RenewRequestResponse | null>(
    null
  )
  const [renewError, setRenewError] = useState<string | null>(null)

  // Handle Live OCSP Test
  const handleRunOcspTest = async () => {
    const hex = testSerial.trim().replace(/[^0-9a-fA-F]/g, '')
    if (!hex) return
    setTestLoading(true)
    setTestError(null)
    try {
      const res = await testOcspRequest(hex, includeNonce, httpMethod)
      if (res.error) {
        setTestError(res.error)
        setTestResult(null)
      } else {
        setTestResult(res)
      }
    } catch (err: any) {
      setTestError(
        err?.response?.data?.message ||
          err?.message ||
          'Failed to execute OCSP test'
      )
      setTestResult(null)
    } finally {
      setTestLoading(false)
    }
  }

  // Handle Database Check
  const handleCheck = async () => {
    const hex = serial.trim().replace(/[^0-9a-fA-F]/g, '')
    if (!hex) return
    setLoading(true)
    setResult(null)
    setError(null)
    setRenewResult(null)
    try {
      const data = await checkCertStatus(hex)
      setResult(data)
    } catch (e: unknown) {
      const msg =
        (e as { response?: { status?: number } }).response?.status === 400
          ? 'Invalid serial number format.'
          : 'Failed to contact the admin API. Is the service running?'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleRenew = async () => {
    if (!result) return
    setRenewLoading(true)
    setRenewError(null)
    try {
      const data = await requestCertRenewal(result.serialHex, renewReason)
      setRenewResult(data)
      setRenewOpen(false)
    } catch {
      setRenewError('Renewal request failed. Check the KMS service logs.')
    } finally {
      setRenewLoading(false)
    }
  }

  const isRevoked = result?.status === 'REVOKED'

  return (
    <Box className="page-enter">
      {/* Header */}
      <Box mb="lg">
        <Title order={3} fw={700}>
          Certificate & OCSP Testing
        </Title>
        <Text fz="sm" c="dimmed" mt={4}>
          Test real RFC 6960 OCSP requests (Nonce vs Nonce-Free) to inspect
          dynamic SoftHSM2 signing and verification, or check DB status.
        </Text>
      </Box>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={setActiveTab} mb="lg" color="indigo">
        <Tabs.List>
          <Tabs.Tab
            value="ocsp-tester"
            leftSection={<IconBolt size={16} />}
          >
            Live OCSP Request Tester (RFC 6960)
          </Tabs.Tab>
          <Tabs.Tab
            value="db-lookup"
            leftSection={<IconSearch size={16} />}
          >
            Database Status Lookup
          </Tabs.Tab>
        </Tabs.List>

        {/* =================================================================== */}
        {/* TAB 0: LIVE OCSP REQUEST TESTER                                    */}
        {/* =================================================================== */}
        <Tabs.Panel value="ocsp-tester" pt="md">
          <Card
            p="lg"
            radius="md"
            mb="lg"
            style={{
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Text fw={700} fz="md" mb={4}>
              Configure OCSP Request
            </Text>
            <Text fz="sm" c="dimmed" mb="md">
              Constructs a standard DER-encoded RFC 6960 OCSP request and
              measures response latency, signature verification, and nonce
              echoing.
            </Text>

            {/* Quick presets */}
            <Group gap="xs" mb="md" wrap="wrap">
              <Text fz="xs" c="dimmed">
                Quick Presets:
              </Text>
              <Badge
                color="teal"
                variant="light"
                style={{ cursor: 'pointer' }}
                onClick={() =>
                  setTestSerial('00b59d41baf78afe0de1bbe7ae28c0450f')
                }
              >
                ee-01 (GOOD)
              </Badge>
              <Badge
                color="red"
                variant="light"
                style={{ cursor: 'pointer' }}
                onClick={() =>
                  setTestSerial('008a5232e619344f2ebdb9b35f93e6a70d')
                }
              >
                ee-02 (REVOKED)
              </Badge>
              <Badge
                color="yellow"
                variant="light"
                style={{ cursor: 'pointer' }}
                onClick={() =>
                  setTestSerial('00dcd6e3751e8e68a43f3fc6561007e833')
                }
              >
                ee-03 (HOLD / GOOD)
              </Badge>
            </Group>

            <Grid gutter="md">
              <Grid.Col span={{ base: 12, md: 7 }}>
                <TextInput
                  label="Certificate Serial Number (hex)"
                  description="Target end-entity certificate serial"
                  value={testSerial}
                  onChange={(e) => setTestSerial(e.target.value)}
                  leftSection={<IconKey size={16} color="#818cf8" />}
                  styles={{
                    input: {
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '0.85rem',
                    },
                  }}
                />
              </Grid.Col>

              <Grid.Col span={{ base: 12, md: 5 }}>
                <Text fz="xs" fw={500} c="dimmed" mb={6}>
                  Transport Protocol
                </Text>
                <Radio.Group
                  value={httpMethod}
                  onChange={(val) => setHttpMethod(val as 'POST' | 'GET')}
                >
                  <Group mt="xs">
                    <Radio value="POST" label="POST (DER binary)" />
                    <Radio value="GET" label="GET (base64url)" />
                  </Group>
                </Radio.Group>
              </Grid.Col>

              <Grid.Col span={12}>
                <Paper
                  p="md"
                  radius="sm"
                  style={{
                    backgroundColor: 'var(--mantine-color-dark-5)',
                    border: '1px solid var(--mantine-color-dark-4)',
                  }}
                >
                  <Switch
                    checked={includeNonce}
                    onChange={(e) => setIncludeNonce(e.currentTarget.checked)}
                    label="Include Nonce Extension (RFC 6960 §4.4.1)"
                    color="indigo"
                  />
                  <Text
                    fz="xs"
                    c={includeNonce ? 'yellow.5' : 'teal.4'}
                    mt={6}
                  >
                    {includeNonce
                      ? '⚠️ NONCE INCLUDED: Injects an 8-byte unique random nonce. Responder echoes it back in the signature.'
                      : '⚡ NONCE-FREE: Standard RFC 6960 query without nonce.'}
                  </Text>
                </Paper>
              </Grid.Col>
            </Grid>

            <Group justify="flex-end" mt="lg">
              <Button
                size="md"
                onClick={handleRunOcspTest}
                disabled={testLoading || !testSerial.trim()}
                loading={testLoading}
                leftSection={<IconBolt size={18} />}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                }}
              >
                Send OCSP Request
              </Button>
            </Group>
          </Card>

          {testError && (
            <Alert
              icon={<IconAlertCircle size={16} />}
              color="red"
              title="Request Error"
              mb="lg"
            >
              {testError}
            </Alert>
          )}

          {/* Test results */}
          {testResult && (
            <Card
              p="lg"
              radius="md"
              mb="lg"
              style={{
                backgroundColor: 'var(--mantine-color-dark-6)',
                border: '1px solid rgba(99,102,241,0.4)',
              }}
            >
              <Group justify="space-between" align="center" mb="md">
                <Group gap="sm">
                  <StatusBadge status={testResult.certStatus} />
                  <Title order={4} fw={700}>
                    OCSP Response Received
                  </Title>
                </Group>

                <Badge
                  leftSection={<IconGauge size={14} />}
                  color={testResult.latencyMs < 10 ? 'teal' : 'indigo'}
                  variant="filled"
                  size="lg"
                >
                  {testResult.latencyMs} ms
                </Badge>
              </Group>

              {/* KPI Banner */}
              <Grid gutter="md" mb="md">
                <Grid.Col span={{ base: 12, sm: 4 }}>
                  <Paper
                    p="sm"
                    radius="sm"
                    style={{
                      backgroundColor: 'rgba(34,197,94,0.08)',
                      border: '1px solid rgba(34,197,94,0.3)',
                    }}
                  >
                    <Text fz="xs" c="dimmed">
                      Signing Architecture
                    </Text>
                    <Group gap="xs" mt={4}>
                      <IconCpu size={18} color="#22c55e" />
                      <Text fz="sm" fw={700} c="teal.4">
                        ⚡ DIRECT SIGNING (NO CACHE)
                      </Text>
                    </Group>
                  </Paper>
                </Grid.Col>

                <Grid.Col span={{ base: 12, sm: 4 }}>
                  <Paper
                    p="sm"
                    radius="sm"
                    style={{
                      backgroundColor: 'var(--mantine-color-dark-5)',
                      border: '1px solid var(--mantine-color-dark-4)',
                    }}
                  >
                    <Text fz="xs" c="dimmed">
                      Nonce Status
                    </Text>
                    <Text
                      fz="sm"
                      fw={700}
                      mt={4}
                      c={
                        testResult.includeNonce
                          ? testResult.nonceMatched
                            ? 'teal.4'
                            : 'red.4'
                          : 'dimmed'
                      }
                    >
                      {testResult.includeNonce
                        ? testResult.nonceMatched
                          ? '✅ Nonce Echoed & Matched'
                          : '❌ Nonce Mismatch'
                        : 'None (Nonce-Free Request)'}
                    </Text>
                  </Paper>
                </Grid.Col>

                <Grid.Col span={{ base: 12, sm: 4 }}>
                  <Paper
                    p="sm"
                    radius="sm"
                    style={{
                      backgroundColor: 'var(--mantine-color-dark-5)',
                      border: '1px solid var(--mantine-color-dark-4)',
                    }}
                  >
                    <Text fz="xs" c="dimmed">
                      Response Size
                    </Text>
                    <Text fz="sm" fw={700} mt={4}>
                      {testResult.responseSizeBytes} bytes (DER)
                    </Text>
                  </Paper>
                </Grid.Col>
              </Grid>

              {/* Detail rows */}
              <Stack gap={0} mb="md">
                <DetailRow
                  label="Target Serial"
                  value={testResult.serialHex}
                  mono
                />
                <DetailRow
                  label="Certificate Status"
                  value={testResult.certStatus}
                />
                {testResult.revocationTime && (
                  <DetailRow
                    label="Revocation Time"
                    value={testResult.revocationTime}
                  />
                )}
                {testResult.revocationReason && (
                  <DetailRow
                    label="Revocation Reason"
                    value={testResult.revocationReason}
                  />
                )}
                <DetailRow
                  label="This Update"
                  value={testResult.thisUpdate}
                />
                <DetailRow
                  label="Next Update"
                  value={testResult.nextUpdate}
                />
                {testResult.nonceSent && (
                  <DetailRow
                    label="Nonce Sent"
                    value={`0x${testResult.nonceSent}`}
                    mono
                  />
                )}
                {testResult.nonceEchoed && (
                  <DetailRow
                    label="Nonce Echoed"
                    value={`0x${testResult.nonceEchoed}`}
                    mono
                  />
                )}
                <DetailRow
                  label="Signing Mode"
                  value={testResult.cacheVerdict}
                />
              </Stack>

              {/* Terminal command */}
              <Box mt="md">
                <Group justify="space-between" mb={6}>
                  <Group gap={6}>
                    <IconTerminal2 size={16} color="#818cf8" />
                    <Text fz="xs" fw={700} c="indigo.3">
                      TERMINAL / OPENSSL EQUIVALENT
                    </Text>
                  </Group>

                  <Button
                    size="compact-xs"
                    variant="subtle"
                    color={copiedCmd ? 'teal' : 'indigo'}
                    leftSection={
                      copiedCmd ? (
                        <IconCheck size={14} />
                      ) : (
                        <IconCopy size={14} />
                      )
                    }
                    onClick={() => {
                      navigator.clipboard.writeText(testResult.opensslCommand)
                      setCopiedCmd(true)
                      setTimeout(() => setCopiedCmd(false), 2000)
                    }}
                  >
                    {copiedCmd ? 'Copied Command!' : 'Copy OpenSSL Command'}
                  </Button>
                </Group>

                <Paper
                  p="sm"
                  radius="sm"
                  style={{
                    backgroundColor: '#080c14',
                    border: '1px solid var(--mantine-color-dark-4)',
                  }}
                >
                  <Text
                    fz="xs"
                    ff="'JetBrains Mono', monospace"
                    c="indigo.2"
                    style={{
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}
                  >
                    {testResult.opensslCommand}
                  </Text>
                </Paper>
              </Box>
            </Card>
          )}
        </Tabs.Panel>

        {/* =================================================================== */}
        {/* TAB 1: DATABASE STATUS LOOKUP & RENEWAL                            */}
        {/* =================================================================== */}
        <Tabs.Panel value="db-lookup" pt="md">
          <Card
            p="lg"
            radius="md"
            mb="lg"
            style={{
              backgroundColor: 'var(--mantine-color-dark-6)',
              border: '1px solid var(--mantine-color-dark-4)',
            }}
          >
            <Group align="flex-start" gap="md">
              <Box style={{ flex: 1 }}>
                <TextInput
                  id="serial-input"
                  label="Certificate Serial Number (hex)"
                  placeholder="e.g. 00b59d41baf78afe0de1bbe7ae28c0450f"
                  value={serial}
                  onChange={(e) => setSerial(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
                  leftSection={<IconKey size={16} color="#6366f1" />}
                  description="Enter the hex-encoded serial number of the certificate to check"
                  styles={{
                    input: {
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '0.85rem',
                    },
                  }}
                />
              </Box>
              <Button
                id="check-cert-btn"
                onClick={handleCheck}
                disabled={loading || !serial.trim()}
                loading={loading}
                leftSection={<IconSearch size={16} />}
                mt={24}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                  minWidth: 140,
                }}
              >
                Check Status
              </Button>
            </Group>
          </Card>

          {error && (
            <Alert
              icon={<IconAlertCircle size={16} />}
              color="red"
              title="Lookup Error"
              mb="lg"
            >
              {error}
            </Alert>
          )}

          <Collapse in={!!result}>
            {result && (
              <Card
                p="lg"
                radius="md"
                mb="lg"
                style={{
                  backgroundColor: 'var(--mantine-color-dark-6)',
                  border: `1px solid ${
                    result.status === 'GOOD'
                      ? 'rgba(34,197,94,0.3)'
                      : result.status === 'REVOKED'
                      ? 'rgba(244,63,94,0.3)'
                      : 'rgba(245,158,11,0.3)'
                  }`,
                }}
              >
                <Group justify="space-between" align="center" mb="md">
                  <Group gap="sm">
                    <StatusBadge status={result.status} />
                    <Text fz="sm" c="dimmed">
                      Certificate is{' '}
                      <strong style={{ color: 'var(--mantine-color-dark-0)' }}>
                        {result.status}
                      </strong>
                    </Text>
                  </Group>

                  <Button
                    id="copy-serial-btn"
                    size="xs"
                    variant="default"
                    leftSection={<IconCopy size={14} />}
                    onClick={() =>
                      navigator.clipboard.writeText(result.serialHex)
                    }
                  >
                    Copy Serial
                  </Button>
                </Group>

                <Stack gap={0} mb="md">
                  <DetailRow
                    label="Serial Number"
                    value={result.serialHex}
                    mono
                  />
                  <DetailRow label="Status" value={result.status} />
                  <DetailRow
                    label="Revoked at"
                    value={
                      result.revocationTime
                        ? new Date(result.revocationTime).toLocaleString()
                        : null
                    }
                  />
                  <DetailRow label="Reason" value={result.revocationReason} />
                </Stack>

                {result.status === 'GOOD' && (
                  <Alert
                    icon={<IconShieldCheck size={18} />}
                    color="teal"
                    title="Good Standing"
                  >
                    This certificate is{' '}
                    <strong>valid and in good standing</strong>. No action
                    required.
                  </Alert>
                )}

                {result.status === 'UNKNOWN' && (
                  <Alert
                    icon={<IconHelp size={18} />}
                    color="yellow"
                    title="Unknown Certificate"
                  >
                    This serial number is <strong>not found</strong> in the OCSP
                    database. The certificate may have been issued by a different
                    CA or may not yet be synchronised.
                  </Alert>
                )}

                {isRevoked && !renewResult && (
                  <Alert
                    icon={<IconShieldX size={18} />}
                    color="red"
                    title="Certificate Revoked"
                  >
                    <Group justify="space-between" align="center" mt="xs">
                      <Text fz="sm">
                        This certificate has been <strong>revoked</strong>. You
                        can request KMS to issue a replacement signing
                        certificate.
                      </Text>
                      <Button
                        id="request-renewal-btn"
                        color="red"
                        variant="light"
                        size="xs"
                        leftSection={<IconRefresh size={14} />}
                        onClick={() => setRenewOpen(true)}
                      >
                        Request Renewal
                      </Button>
                    </Group>
                  </Alert>
                )}

                {renewResult && (
                  <Alert
                    icon={<IconRefresh size={18} />}
                    color="teal"
                    title="Renewal Request Accepted by KMS"
                    mt="md"
                  >
                    <Stack gap={0} mt="xs">
                      <DetailRow
                        label="Request ID"
                        value={renewResult.requestId}
                        mono
                      />
                      <DetailRow
                        label="KMS Status"
                        value={renewResult.kmsStatus}
                      />
                      <DetailRow
                        label="New valid until"
                        value={
                          renewResult.newNotAfter
                            ? new Date(
                                renewResult.newNotAfter
                              ).toLocaleString()
                            : null
                        }
                      />
                      <DetailRow
                        label="Submitted at"
                        value={new Date(
                          renewResult.submittedAt
                        ).toLocaleString()}
                      />
                    </Stack>
                  </Alert>
                )}
              </Card>
            )}
          </Collapse>
        </Tabs.Panel>
      </Tabs>

      {/* Renewal modal */}
      <Modal
        opened={renewOpen}
        onClose={() => setRenewOpen(false)}
        title={
          <Group gap="xs">
            <IconRefresh size={20} color="#6366f1" />
            <Text fw={700} fz="md">
              Request KMS Cert Renewal
            </Text>
          </Group>
        }
        centered
        radius="md"
        styles={{
          content: {
            backgroundColor: 'var(--mantine-color-dark-6)',
            border: '1px solid var(--mantine-color-dark-4)',
          },
        }}
      >
        <Text fz="sm" c="dimmed" mb="md">
          This will call the KMS service to rotate the OCSP signing certificate.
          The old revoked certificate will be replaced with a fresh 90-day cert.
        </Text>

        <Textarea
          id="renewal-reason-input"
          label="Renewal Reason"
          value={renewReason}
          onChange={(e) => setRenewReason(e.target.value)}
          rows={3}
          mb="md"
        />

        {renewError && (
          <Alert
            icon={<IconAlertCircle size={16} />}
            color="red"
            title="Renewal Failed"
            mb="md"
          >
            {renewError}
          </Alert>
        )}

        <Group justify="flex-end" mt="lg">
          <Button
            id="cancel-renewal-btn"
            variant="default"
            onClick={() => setRenewOpen(false)}
          >
            Cancel
          </Button>
          <Button
            id="confirm-renewal-btn"
            onClick={handleRenew}
            loading={renewLoading}
            leftSection={<IconRefresh size={16} />}
            style={{
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            }}
          >
            Confirm Renewal
          </Button>
        </Group>
      </Modal>
    </Box>
  )
}
