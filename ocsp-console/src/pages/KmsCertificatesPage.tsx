import { useState, useEffect, useMemo } from 'react'
import {
  Box,
  Title,
  Text,
  Card,
  Grid,
  Table,
  TextInput,
  Button,
  ActionIcon,
  Badge,
  Modal,
  Select,
  Alert,
  Tooltip,
  Paper,
  Pagination,
  Group,
  Stack,
  Skeleton,
} from '@mantine/core'
import {
  IconSearch,
  IconRefresh,
  IconKey,
  IconShieldCheck,
  IconShieldX,
  IconPlayerPause,
  IconPlayerPlay,
  IconCopy,
  IconDownload,
  IconEye,
  IconAlertTriangle,
  IconX,
  IconFilter,
  IconCheck,
  IconAlertCircle,
  IconInfoCircle,
} from '@tabler/icons-react'
import {
  getKmsCertificates,
  revokeKmsCertificate,
  unrevokeKmsCertificate,
  updateKmsCertificateStatus,
  triggerKmsRevocationJob,
} from '../api/client'
import type { KmsCertificate, KmsRevocationReason } from '../types/api'

// ---------------------------------------------------------------------------
// RFC 5280 Reasons Metadata
// ---------------------------------------------------------------------------
const RFC_5280_REASONS: {
  code: KmsRevocationReason
  label: string
  description: string
}[] = [
  {
    code: 'KEY_COMPROMISE',
    label: 'Key Compromise (1)',
    description: 'Private key was compromised or suspected compromised',
  },
  {
    code: 'CA_COMPROMISE',
    label: 'CA Compromise (2)',
    description: 'Issuing CA private key or authority was compromised',
  },
  {
    code: 'AFFILIATION_CHANGED',
    label: 'Affiliation Changed (3)',
    description:
      'Subject name, organizational affiliation, or identity changed',
  },
  {
    code: 'SUPERSEDED',
    label: 'Superseded (4)',
    description: 'Certificate was replaced by a new certificate',
  },
  {
    code: 'CESSATION_OF_OPERATION',
    label: 'Cessation of Operation (5)',
    description:
      'Server, domain, or service has permanently ceased operation',
  },
  {
    code: 'CERTIFICATE_HOLD',
    label: 'Certificate Hold / Suspension (6)',
    description:
      'Temporary suspension — can be un-revoked / reinstated back to GOOD later',
  },
  {
    code: 'PRIVILEGE_WITHDRAWN',
    label: 'Privilege Withdrawn (9)',
    description:
      'Subject privileges, credentials, or certifications were revoked',
  },
  {
    code: 'AA_COMPROMISE',
    label: 'AA Compromise (10)',
    description: 'Attribute Authority private key was compromised',
  },
  {
    code: 'UNSPECIFIED',
    label: 'Unspecified (0)',
    description: 'No specific reason provided',
  },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatDate(iso: string | null): string {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
  } catch {
    return iso
  }
}

function truncateSerial(hex: string): string {
  if (!hex || hex.length <= 16) return hex
  return `${hex.substring(0, 8)}...${hex.substring(hex.length - 8)}`
}

function copyToClipboard(text: string, onCopy?: () => void) {
  navigator.clipboard.writeText(text)
  if (onCopy) onCopy()
}

function downloadPem(pem: string, filename: string) {
  const blob = new Blob([pem], { type: 'application/x-x509-ca-cert' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export function KmsCertificatesPage() {
  const [certificates, setCertificates] = useState<KmsCertificate[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [alert, setAlert] = useState<{
    type: 'teal' | 'red' | 'indigo'
    message: string
  } | null>(null)

  // Filters
  const [search, setSearch] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('ALL')

  // Pagination
  const [page, setPage] = useState<number>(0)
  const pageSize = 10

  // Revoke Dialog
  const [revokeDialogOpen, setRevokeDialogOpen] = useState<boolean>(false)
  const [targetCert, setTargetCert] = useState<KmsCertificate | null>(null)
  const [revokeReason, setRevokeReason] = useState<string>('KEY_COMPROMISE')
  const [actionLoading, setActionLoading] = useState<boolean>(false)

  // Status Update Dialog (Any status: GOOD, REVOKED, HOLD)
  const [statusModalOpen, setStatusModalOpen] = useState<boolean>(false)
  const [statusModalCert, setStatusModalCert] = useState<KmsCertificate | null>(null)
  const [targetStatus, setTargetStatus] = useState<'GOOD' | 'REVOKED' | 'CERTIFICATE_HOLD'>('REVOKED')
  const [targetReason, setTargetReason] = useState<string>('KEY_COMPROMISE')
  const [targetRevTime, setTargetRevTime] = useState<string>('')

  const openStatusUpdateModal = (cert: KmsCertificate) => {
    setStatusModalCert(cert)
    const initialStatus =
      cert.status === 'GOOD'
        ? 'REVOKED'
        : cert.revocationReason === 'CERTIFICATE_HOLD'
        ? 'CERTIFICATE_HOLD'
        : 'GOOD'
    setTargetStatus(initialStatus)
    setTargetReason(cert.revocationReason || 'KEY_COMPROMISE')
    setTargetRevTime(cert.revocationTime ? cert.revocationTime.slice(0, 16) : '')
    setStatusModalOpen(true)
  }

  const handleUpdateStatusSubmit = async () => {
    if (!statusModalCert) return
    setActionLoading(true)
    try {
      await updateKmsCertificateStatus(
        statusModalCert.serialNumberHex,
        targetStatus,
        targetStatus === 'GOOD' ? undefined : targetReason,
        targetStatus === 'GOOD' ? undefined : (targetRevTime ? new Date(targetRevTime).toISOString() : new Date().toISOString())
      )
      setAlert({
        type: 'teal',
        message: `Status for ${statusModalCert.serialNumberHex.slice(0, 8)}... updated to ${targetStatus}!`,
      })
      setStatusModalOpen(false)
      fetchCertificates()
    } catch (err: any) {
      setAlert({
        type: 'red',
        message: `Failed to update status: ${err.response?.data?.error || err.message}`,
      })
    } finally {
      setActionLoading(false)
    }
  }

  // Details & PEM Dialog
  const [detailsDialogOpen, setDetailsDialogOpen] = useState<boolean>(false)
  const [detailsCert, setDetailsCert] = useState<KmsCertificate | null>(null)
  const [copiedPem, setCopiedPem] = useState<boolean>(false)
  const [copiedSerial, setCopiedSerial] = useState<string | null>(null)

  // Simulator Job Trigger
  const [jobTriggerLoading, setJobTriggerLoading] = useState<boolean>(false)

  // Load certificates
  const fetchCertificates = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getKmsCertificates()
      setCertificates(data)
    } catch (err: any) {
      setError(
        err?.response?.data?.message ||
          err?.message ||
          'Failed to load KMS certificates'
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCertificates()
  }, [])

  // Derived metrics
  const now = new Date()
  const metrics = useMemo(() => {
    let good = 0
    let revoked = 0
    let hold = 0
    let expiredSoon = 0

    certificates.forEach((c) => {
      if (c.status === 'GOOD') {
        good++
      } else if (c.status === 'REVOKED') {
        revoked++
        if (c.revocationReason === 'CERTIFICATE_HOLD') {
          hold++
        }
      }

      try {
        const notAfter = new Date(c.notAfter)
        const daysLeft =
          (notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        if (daysLeft <= 30) {
          expiredSoon++
        }
      } catch {
        /* ignore */
      }
    })

    return { total: certificates.length, good, revoked, hold, expiredSoon }
  }, [certificates, now])

  // Filtered certificates
  const filteredCerts = useMemo(() => {
    const s = search.trim().toLowerCase()
    return certificates.filter((c) => {
      if (statusFilter === 'GOOD' && c.status !== 'GOOD') return false
      if (statusFilter === 'REVOKED' && c.status !== 'REVOKED') return false
      if (
        statusFilter === 'HOLD' &&
        !(c.status === 'REVOKED' && c.revocationReason === 'CERTIFICATE_HOLD')
      )
        return false

      if (s) {
        const matchSerial = c.serialNumberHex.toLowerCase().includes(s)
        const matchSubject = c.subjectDn.toLowerCase().includes(s)
        const matchIssuer = c.issuerDn.toLowerCase().includes(s)
        if (!matchSerial && !matchSubject && !matchIssuer) return false
      }

      return true
    })
  }, [certificates, statusFilter, search])

  // Handle Revoke
  const openRevokeModal = (cert: KmsCertificate) => {
    setTargetCert(cert)
    setRevokeReason('KEY_COMPROMISE')
    setRevokeDialogOpen(true)
  }

  const handleConfirmRevoke = async () => {
    if (!targetCert) return
    setActionLoading(true)
    try {
      await revokeKmsCertificate(targetCert.serialNumberHex, revokeReason)
      setAlert({
        type: 'teal',
        message: `Certificate ${truncateSerial(
          targetCert.serialNumberHex
        )} revoked (${revokeReason}). Event published to RabbitMQ!`,
      })
      setRevokeDialogOpen(false)
      fetchCertificates()
    } catch (err: any) {
      setAlert({
        type: 'red',
        message:
          err?.response?.data?.error ||
          err?.message ||
          'Revocation failed',
      })
    } finally {
      setActionLoading(false)
    }
  }

  // Handle Unrevoke (release CERTIFICATE_HOLD)
  const handleUnrevoke = async (cert: KmsCertificate) => {
    setActionLoading(true)
    try {
      await unrevokeKmsCertificate(cert.serialNumberHex)
      setAlert({
        type: 'teal',
        message: `Certificate ${truncateSerial(
          cert.serialNumberHex
        )} hold released. Reinstated to GOOD!`,
      })
      fetchCertificates()
    } catch (err: any) {
      setAlert({
        type: 'red',
        message:
          err?.response?.data?.error ||
          err?.message ||
          'Un-revocation failed',
      })
    } finally {
      setActionLoading(false)
    }
  }

  // Handle Simulator Job Trigger
  const handleTriggerJob = async () => {
    setJobTriggerLoading(true)
    try {
      await triggerKmsRevocationJob()
      setAlert({
        type: 'indigo',
        message:
          'KMS Simulator job executed: random GOOD certs revoked / HOLD certs unrevoked. RabbitMQ events published.',
      })
      setTimeout(() => {
        fetchCertificates()
        setJobTriggerLoading(false)
      }, 500)
    } catch (err: any) {
      setAlert({
        type: 'red',
        message:
          err?.response?.data?.error ||
          err?.message ||
          'Failed to trigger revocation job',
      })
      setJobTriggerLoading(false)
    }
  }

  // Details modal
  const openDetailsModal = (cert: KmsCertificate) => {
    setDetailsCert(cert)
    setCopiedPem(false)
    setDetailsDialogOpen(true)
  }

  const totalPages = Math.ceil(filteredCerts.length / pageSize)

  return (
    <Box className="page-enter">
      {/* Header */}
      <Group justify="space-between" align="flex-start" mb="lg">
        <Box>
          <Group gap="sm">
            <IconKey size={30} color="#818cf8" />
            <Title order={3} fw={700}>
              KMS Certificate Manager
            </Title>
          </Group>
          <Text fz="sm" c="dimmed" mt={4}>
            Source of truth certificate inventory — Incert Test PKI simulation
            with Transactional Outbox event publishing
          </Text>
        </Box>

        <Group gap="sm">
          <Button
            variant="default"
            leftSection={<IconRefresh size={16} />}
            onClick={fetchCertificates}
            disabled={loading}
          >
            Refresh
          </Button>

          <Button
            leftSection={<IconPlayerPlay size={16} />}
            onClick={handleTriggerJob}
            loading={jobTriggerLoading}
            style={{
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            }}
          >
            Run Revocation Job
          </Button>
        </Group>
      </Group>

      {/* Notifications / Alerts */}
      {alert && (
        <Alert
          color={alert.type}
          icon={
            alert.type === 'teal' ? (
              <IconCheck size={16} />
            ) : alert.type === 'red' ? (
              <IconAlertCircle size={16} />
            ) : (
              <IconInfoCircle size={16} />
            )
          }
          withCloseButton
          onClose={() => setAlert(null)}
          mb="lg"
        >
          {alert.message}
        </Alert>
      )}

      {error && (
        <Alert
          icon={<IconAlertCircle size={16} />}
          color="red"
          title="Error"
          mb="lg"
        >
          {error}
        </Alert>
      )}

      {/* Metrics Cards */}
      <Grid gutter="sm" mb="lg">
        {[
          { label: 'Total Certs', value: metrics.total, color: 'dimmed' },
          { label: 'Good / Active', value: metrics.good, color: 'teal.4' },
          { label: 'Revoked (Total)', value: metrics.revoked, color: 'red.4' },
          { label: 'On Hold (Suspended)', value: metrics.hold, color: 'yellow.5' },
          { label: 'Near Expiry (≤30d)', value: metrics.expiredSoon, color: 'blue.4' },
        ].map(({ label, value, color }) => (
          <Grid.Col span={{ base: 6, sm: 4, md: 2.4 }} key={label}>
            <Card
              p="sm"
              radius="md"
              style={{
                backgroundColor: 'var(--mantine-color-dark-6)',
                border: '1px solid var(--mantine-color-dark-4)',
              }}
            >
              <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
                {label}
              </Text>
              <Text fz={26} fw={700} mt={4} c={color}>
                {value}
              </Text>
            </Card>
          </Grid.Col>
        ))}
      </Grid>

      {/* Filter and Search Bar */}
      <Card
        p="sm"
        radius="md"
        mb="lg"
        style={{
          backgroundColor: 'var(--mantine-color-dark-6)',
          border: '1px solid var(--mantine-color-dark-4)',
        }}
      >
        <Grid gutter="sm" align="center">
          <Grid.Col span={{ base: 12, md: 6 }}>
            <TextInput
              placeholder="Search by Serial Hex or Subject DN..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
              leftSection={<IconSearch size={16} color="#64748b" />}
              rightSection={
                search ? (
                  <ActionIcon
                    size="sm"
                    variant="subtle"
                    onClick={() => setSearch('')}
                  >
                    <IconX size={14} />
                  </ActionIcon>
                ) : null
              }
            />
          </Grid.Col>

          <Grid.Col span={{ base: 12, md: 4 }}>
            <Select
              placeholder="Filter Status"
              value={statusFilter}
              onChange={(val) => {
                setStatusFilter(val || 'ALL')
                setPage(0)
              }}
              leftSection={<IconFilter size={16} color="#64748b" />}
              data={[
                { value: 'ALL', label: `All Certificates (${metrics.total})` },
                { value: 'GOOD', label: `Good / Active (${metrics.good})` },
                { value: 'REVOKED', label: `Revoked (${metrics.revoked})` },
                { value: 'HOLD', label: `On Hold / Suspended (${metrics.hold})` },
              ]}
            />
          </Grid.Col>

          <Grid.Col span={{ base: 12, md: 2 }}>
            <Text fz="xs" c="dimmed" ta={{ base: 'left', md: 'right' }}>
              Showing {filteredCerts.length} of {certificates.length}
            </Text>
          </Grid.Col>
        </Grid>
      </Card>

      {/* Certificates Table */}
      <Card
        p="md"
        radius="md"
        style={{
          backgroundColor: 'var(--mantine-color-dark-6)',
          border: '1px solid var(--mantine-color-dark-4)',
        }}
      >
        <Table.ScrollContainer minWidth={850}>
          <Table verticalSpacing="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Serial Number</Table.Th>
                <Table.Th>Subject DN</Table.Th>
                <Table.Th>Validity Window</Table.Th>
                <Table.Th>Status / Reason</Table.Th>
                <Table.Th style={{ width: 80 }}>Seq</Table.Th>
                <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <Table.Tr key={i}>
                    {Array.from({ length: 6 }).map((_, j) => (
                      <Table.Td key={j}>
                        <Skeleton height={18} radius="sm" />
                      </Table.Td>
                    ))}
                  </Table.Tr>
                ))
              ) : filteredCerts.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text ta="center" c="dimmed" py="xl">
                      No certificates match the selected filter or search term.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                filteredCerts
                  .slice(page * pageSize, page * pageSize + pageSize)
                  .map((cert) => {
                    const isGood = cert.status === 'GOOD'
                    const isHold =
                      cert.status === 'REVOKED' &&
                      cert.revocationReason === 'CERTIFICATE_HOLD'

                    let expiryBadge: React.ReactNode = null
                    try {
                      const notAfter = new Date(cert.notAfter)
                      const diffDays = Math.ceil(
                        (notAfter.getTime() - now.getTime()) /
                          (1000 * 60 * 60 * 24)
                      )
                      if (diffDays < 0) {
                        expiryBadge = (
                          <Badge color="red" variant="light" size="xs">
                            Expired {Math.abs(diffDays)}d ago
                          </Badge>
                        )
                      } else if (diffDays <= 30) {
                        expiryBadge = (
                          <Badge color="yellow" variant="light" size="xs">
                            Expiring in {diffDays}d
                          </Badge>
                        )
                      }
                    } catch {
                      /* ignore */
                    }

                    return (
                      <Table.Tr key={cert.serialNumberHex}>
                        {/* Serial */}
                        <Table.Td>
                          <Group gap={6} wrap="nowrap">
                            <Tooltip
                              label={cert.serialNumberHex}
                              withArrow
                              position="top"
                            >
                              <Text
                                fz="xs"
                                ff="'JetBrains Mono', monospace"
                                fw={600}
                                c="indigo.2"
                                style={{ cursor: 'pointer' }}
                                onClick={() => openDetailsModal(cert)}
                              >
                                {truncateSerial(cert.serialNumberHex)}
                              </Text>
                            </Tooltip>
                            <Tooltip label="Copy full serial hex" withArrow>
                              <ActionIcon
                                size="xs"
                                variant="subtle"
                                onClick={() => {
                                  copyToClipboard(
                                    cert.serialNumberHex,
                                    () => {
                                      setCopiedSerial(cert.serialNumberHex)
                                      setTimeout(
                                        () => setCopiedSerial(null),
                                        1500
                                      )
                                    }
                                  )
                                }}
                              >
                                {copiedSerial === cert.serialNumberHex ? (
                                  <IconCheck size={12} color="#22c55e" />
                                ) : (
                                  <IconCopy size={12} color="#64748b" />
                                )}
                              </ActionIcon>
                            </Tooltip>
                          </Group>
                        </Table.Td>

                        {/* Subject DN */}
                        <Table.Td>
                          <Text fz="xs" fw={500}>
                            {cert.subjectDn}
                          </Text>
                          <Text fz={11} c="dimmed">
                            Issuer: {cert.issuerDn}
                          </Text>
                        </Table.Td>

                        {/* Validity */}
                        <Table.Td>
                          <Stack gap={2}>
                            <Text fz="xs" c="dimmed">
                              {formatDate(cert.notBefore)} &rarr;{' '}
                              {formatDate(cert.notAfter)}
                            </Text>
                            {expiryBadge}
                          </Stack>
                        </Table.Td>

                        {/* Status */}
                        <Table.Td>
                          {isGood ? (
                            <Badge
                              leftSection={<IconShieldCheck size={12} />}
                              color="teal"
                              variant="light"
                              size="sm"
                            >
                              GOOD
                            </Badge>
                          ) : isHold ? (
                            <Badge
                              leftSection={<IconPlayerPause size={12} />}
                              color="yellow"
                              variant="light"
                              size="sm"
                            >
                              ON HOLD
                            </Badge>
                          ) : (
                            <Stack gap={2}>
                              <Badge
                                leftSection={<IconShieldX size={12} />}
                                color="red"
                                variant="light"
                                size="sm"
                              >
                                REVOKED
                              </Badge>
                              <Text fz={11} c="red.4">
                                Reason: {cert.revocationReason || 'UNSPECIFIED'}
                              </Text>
                            </Stack>
                          )}
                        </Table.Td>

                        {/* Seq */}
                        <Table.Td>
                          <Badge color="gray" variant="light" size="xs">
                            v{cert.sequence}
                          </Badge>
                        </Table.Td>

                        {/* Actions */}
                        <Table.Td style={{ textAlign: 'right' }}>
                          <Group gap="xs" justify="flex-end" wrap="nowrap">
                            {isGood && (
                              <Button
                                size="compact-xs"
                                variant="outline"
                                color="red"
                                onClick={() => openRevokeModal(cert)}
                              >
                                Revoke
                              </Button>
                            )}

                            {isHold && (
                              <Button
                                size="compact-xs"
                                variant="filled"
                                color="yellow"
                                disabled={actionLoading}
                                onClick={() => handleUnrevoke(cert)}
                              >
                                Release Hold
                              </Button>
                            )}

                            <Button
                              size="compact-xs"
                              variant="default"
                              onClick={() => openStatusUpdateModal(cert)}
                            >
                              Edit Status
                            </Button>

                            <Tooltip
                              label="View Certificate Details & PEM"
                              withArrow
                            >
                              <ActionIcon
                                size="sm"
                                variant="light"
                                color="indigo"
                                onClick={() => openDetailsModal(cert)}
                              >
                                <IconEye size={16} />
                              </ActionIcon>
                            </Tooltip>
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    )
                  })
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>

        {totalPages > 1 && (
          <Group justify="center" mt="md" py="xs">
            <Pagination
              total={totalPages}
              value={page + 1}
              onChange={(v) => setPage(v - 1)}
              color="indigo"
              size="sm"
            />
          </Group>
        )}
      </Card>

      {/* =================================================================== */}
      {/* Revocation Modal                                                   */}
      {/* =================================================================== */}
      <Modal
        opened={revokeDialogOpen}
        onClose={() => !actionLoading && setRevokeDialogOpen(false)}
        title={
          <Text fw={700} fz="md">
            Revoke Certificate
          </Text>
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
        {targetCert && (
          <Stack gap="md">
            <Paper
              p="sm"
              radius="sm"
              style={{
                backgroundColor: 'var(--mantine-color-dark-5)',
                border: '1px solid var(--mantine-color-dark-4)',
              }}
            >
              <Text fz="xs" c="dimmed">
                Target Certificate
              </Text>
              <Text fz="sm" fw={600} mt={2}>
                {targetCert.subjectDn}
              </Text>
              <Text
                fz="xs"
                ff="'JetBrains Mono', monospace"
                c="indigo.3"
                mt={4}
              >
                Serial: {targetCert.serialNumberHex}
              </Text>
            </Paper>

            <Select
              label="Revocation Reason (RFC 5280)"
              value={revokeReason}
              onChange={(val) => setRevokeReason(val || 'KEY_COMPROMISE')}
              data={RFC_5280_REASONS.map((r) => ({
                value: r.code,
                label: r.label,
              }))}
            />

            <Alert
              icon={<IconAlertTriangle size={18} />}
              color="yellow"
              title="RabbitMQ Event Propagation"
            >
              Revoking immediately creates a Transactional Outbox record in KMS
              and relays a <code>CertificateStatusChanged</code> event to
              RabbitMQ exchange <code>incert.certificate.status</code>.
            </Alert>

            <Group justify="flex-end" mt="md">
              <Button
                variant="default"
                onClick={() => setRevokeDialogOpen(false)}
                disabled={actionLoading}
              >
                Cancel
              </Button>
              <Button
                color="red"
                onClick={handleConfirmRevoke}
                loading={actionLoading}
                leftSection={<IconShieldX size={16} />}
              >
                Confirm Revocation
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      {/* =================================================================== */}
      {/* Update Certificate Status Modal (GOOD, REVOKED, HOLD)               */}
      {/* =================================================================== */}
      <Modal
        opened={statusModalOpen}
        onClose={() => setStatusModalOpen(false)}
        size="md"
        title={
          <Group gap="xs">
            <IconKey size={20} color="#818cf8" />
            <Text fw={700} fz="md">
              Update Certificate Status
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
        {statusModalCert && (
          <Stack gap="md">
            <Paper
              p="sm"
              radius="sm"
              style={{
                backgroundColor: 'var(--mantine-color-dark-5)',
                border: '1px solid var(--mantine-color-dark-4)',
              }}
            >
              <Text fz="xs" c="dimmed">TARGET CERTIFICATE</Text>
              <Text fw={600} fz="sm" c="white" mt={2}>{statusModalCert.subjectDn}</Text>
              <Text fz="xs" ff="monospace" c="indigo.3" mt={2}>
                Serial: {statusModalCert.serialNumberHex}
              </Text>
              <Text fz="xs" c="dimmed" mt={2}>
                Current Status: <strong>{statusModalCert.status}</strong> (Seq: v{statusModalCert.sequence})
              </Text>
            </Paper>

            <Select
              label="Target Status"
              value={targetStatus}
              onChange={(val) => setTargetStatus((val as any) || 'REVOKED')}
              data={[
                { value: 'GOOD', label: 'GOOD (Active / Valid / Restored)' },
                { value: 'REVOKED', label: 'REVOKED (Revoked)' },
                { value: 'CERTIFICATE_HOLD', label: 'CERTIFICATE_HOLD (Temporary Suspension)' },
              ]}
            />

            {targetStatus !== 'GOOD' && (
              <Select
                label="Revocation Reason (RFC 5280)"
                value={targetReason}
                onChange={(val) => setTargetReason(val || 'KEY_COMPROMISE')}
                data={RFC_5280_REASONS.map((r) => ({
                  value: r.code,
                  label: r.label,
                }))}
              />
            )}

            {targetStatus !== 'GOOD' && (
              <TextInput
                label="Revocation Timestamp (ISO / Local)"
                placeholder="YYYY-MM-DDTHH:MM:SS"
                value={targetRevTime}
                onChange={(e) => setTargetRevTime(e.currentTarget.value)}
                description="Leave blank to use current timestamp"
              />
            )}

            <Alert
              icon={<IconAlertTriangle size={18} />}
              color="indigo"
              title="Transactional Outbox Synchronization"
            >
              Submitting updates status in KMS, increments monotonic sequence to <strong>v{statusModalCert.sequence + 1}</strong>, and automatically publishes an event to RabbitMQ for OCSP Responder ingestion.
            </Alert>

            <Group justify="flex-end" mt="md">
              <Button
                variant="default"
                onClick={() => setStatusModalOpen(false)}
                disabled={actionLoading}
              >
                Cancel
              </Button>
              <Button
                color="indigo"
                onClick={handleUpdateStatusSubmit}
                loading={actionLoading}
                leftSection={<IconCheck size={16} />}
              >
                Save Status Update
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      {/* =================================================================== */}
      {/* Details & PEM Modal                                                */}
      {/* =================================================================== */}
      <Modal
        opened={detailsDialogOpen}
        onClose={() => setDetailsDialogOpen(false)}
        size="lg"
        title={
          <Group gap="xs">
            <IconKey size={20} color="#818cf8" />
            <Text fw={700} fz="md">
              Certificate Details & PEM
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
        {detailsCert && (
          <Stack gap="lg">
            {/* Attributes */}
            <Box>
              <Text fz="xs" fw={700} c="indigo.3" tt="uppercase" mb="xs">
                X.509 ATTRIBUTES
              </Text>

              <Paper
                p="sm"
                radius="sm"
                style={{
                  backgroundColor: 'var(--mantine-color-dark-5)',
                  border: '1px solid var(--mantine-color-dark-4)',
                }}
              >
                <Stack gap={6}>
                  {[
                    {
                      label: 'Serial Number',
                      value: detailsCert.serialNumberHex,
                      mono: true,
                    },
                    { label: 'Subject DN', value: detailsCert.subjectDn },
                    { label: 'Issuer DN', value: detailsCert.issuerDn },
                    {
                      label: 'Issuer Key Hash (SHA-1)',
                      value: detailsCert.issuerKeyHashHex,
                      mono: true,
                    },
                    {
                      label: 'Issuer Name Hash (SHA-1)',
                      value: detailsCert.issuerNameHashHex,
                      mono: true,
                    },
                    {
                      label: 'Validity Period',
                      value: `${formatDate(detailsCert.notBefore)} — ${formatDate(
                        detailsCert.notAfter
                      )}`,
                    },
                    {
                      label: 'Status',
                      value:
                        detailsCert.status === 'GOOD'
                          ? 'GOOD'
                          : `REVOKED (${detailsCert.revocationReason || 'UNSPECIFIED'})`,
                    },
                    {
                      label: 'Sequence',
                      value: `v${detailsCert.sequence}`,
                      mono: true,
                    },
                  ].map(({ label, value, mono }) => (
                    <Group
                      key={label}
                      justify="space-between"
                      align="flex-start"
                      py={4}
                      style={{
                        borderBottom:
                          '1px solid var(--mantine-color-dark-4)',
                      }}
                    >
                      <Text fz="xs" c="dimmed" style={{ minWidth: 140 }}>
                        {label}
                      </Text>
                      <Text
                        fz="xs"
                        ff={mono ? "'JetBrains Mono', monospace" : 'inherit'}
                        ta="right"
                        style={{ wordBreak: 'break-all' }}
                      >
                        {value}
                      </Text>
                    </Group>
                  ))}
                </Stack>
              </Paper>
            </Box>

            {/* PEM Block */}
            <Box>
              <Group justify="space-between" mb="xs">
                <Text fz="xs" fw={700} c="indigo.3" tt="uppercase">
                  PEM CERTIFICATE
                </Text>

                <Group gap="xs">
                  <Button
                    size="compact-xs"
                    variant="subtle"
                    color={copiedPem ? 'teal' : 'indigo'}
                    leftSection={
                      copiedPem ? (
                        <IconCheck size={14} />
                      ) : (
                        <IconCopy size={14} />
                      )
                    }
                    onClick={() => {
                      copyToClipboard(detailsCert.pemEncoded, () => {
                        setCopiedPem(true)
                        setTimeout(() => setCopiedPem(false), 2000)
                      })
                    }}
                  >
                    {copiedPem ? 'Copied!' : 'Copy PEM'}
                  </Button>

                  <Button
                    size="compact-xs"
                    variant="subtle"
                    color="indigo"
                    leftSection={<IconDownload size={14} />}
                    onClick={() =>
                      downloadPem(
                        detailsCert.pemEncoded,
                        `cert-${truncateSerial(
                          detailsCert.serialNumberHex
                        )}.crt`
                      )
                    }
                  >
                    Download .crt
                  </Button>
                </Group>
              </Group>

              <Paper
                p="sm"
                radius="sm"
                style={{
                  backgroundColor: '#080c14',
                  border: '1px solid var(--mantine-color-dark-4)',
                  maxHeight: 220,
                  overflowY: 'auto',
                }}
              >
                <Text
                  fz={11}
                  ff="'JetBrains Mono', monospace"
                  c="indigo.2"
                  style={{
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    margin: 0,
                  }}
                >
                  {detailsCert.pemEncoded}
                </Text>
              </Paper>
            </Box>

            <Group justify="flex-end">
              <Button
                variant="default"
                onClick={() => setDetailsDialogOpen(false)}
              >
                Close
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Box>
  )
}
