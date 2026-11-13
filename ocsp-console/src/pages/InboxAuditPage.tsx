import { useState, useEffect } from 'react'
import {
  Box,
  Title,
  Text,
  Card,
  Grid,
  Table,
  Badge,
  Button,
  Group,
  TextInput,
  Paper,
  Alert,
  Tooltip,
  ActionIcon,
  CopyButton,
  Loader,
} from '@mantine/core'
import {
  IconInbox,
  IconRefresh,
  IconCheck,
  IconAlertTriangle,
  IconSearch,
  IconCopy,
  IconSend,
  IconShieldCheck,
} from '@tabler/icons-react'
import {
  getInboxEvents,
  getInboxStats,
  verifyReconciliation,
  syncAllKmsCertificates,
} from '../api/client'
import type { InboxEventItem, ReconciliationReport } from '../types/api'

export function InboxAuditPage() {
  const [events, setEvents] = useState<InboxEventItem[]>([])
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<{
    totalReceived: number
    processed: number
    duplicate: number
    skipped: number
    failed: number
  } | null>(null)

  const [reconciliation, setReconciliation] = useState<ReconciliationReport | null>(null)
  const [reconLoading, setReconLoading] = useState(false)
  const [syncLoading, setSyncLoading] = useState(false)
  const [searchSerial, setSearchSerial] = useState('')

  const loadData = async () => {
    setLoading(true)
    try {
      const [eventsRes, statsRes] = await Promise.all([
        getInboxEvents(0, 100, searchSerial || undefined),
        getInboxStats(),
      ])
      setEvents(eventsRes.events || [])
      setStats(statsRes)
    } catch (err) {
      console.error('Failed to load inbox data', err)
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyReconciliation = async () => {
    setReconLoading(true)
    try {
      const report = await verifyReconciliation()
      setReconciliation(report)
    } catch (err: any) {
      alert('Reconciliation check failed: ' + (err.response?.data?.error || err.message))
    } finally {
      setReconLoading(false)
    }
  }

  const handleSyncAll = async () => {
    if (!window.confirm('Broadcast all KMS certificates to RabbitMQ outbox to re-populate the responder inbox?')) {
      return
    }
    setSyncLoading(true)
    try {
      const res = await syncAllKmsCertificates()
      alert(`Sync queued: ${res.message}`)
      setTimeout(() => {
        loadData()
        handleVerifyReconciliation()
      }, 1200)
    } catch (err: any) {
      alert('Sync failed: ' + (err.response?.data?.error || err.message))
    } finally {
      setSyncLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    handleVerifyReconciliation()
  }, [])

  return (
    <Box p="md">
      {/* Header */}
      <Group justify="space-between" align="flex-start" mb="lg">
        <div>
          <Group gap="xs">
            <IconInbox size={26} color="#818cf8" />
            <Title order={2} c="white">
              Responder Inbox &amp; Reconciliation Audit
            </Title>
          </Group>
          <Text c="dimmed" fz="sm" mt={4}>
            Records all certificate status events received from RabbitMQ and verifies parity with the KMS source of truth.
          </Text>
        </div>

        <Group gap="xs">
          <Button
            leftSection={<IconRefresh size={16} />}
            variant="default"
            size="sm"
            onClick={loadData}
            loading={loading}
          >
            Refresh
          </Button>

          <Button
            leftSection={<IconShieldCheck size={16} />}
            variant="light"
            color="indigo"
            size="sm"
            onClick={handleVerifyReconciliation}
            loading={reconLoading}
          >
            Verify KMS Sync
          </Button>

          <Button
            leftSection={<IconSend size={16} />}
            variant="gradient"
            gradient={{ from: 'indigo', to: 'violet' }}
            size="sm"
            onClick={handleSyncAll}
            loading={syncLoading}
          >
            Sync All to Responder
          </Button>
        </Group>
      </Group>

      {/* KPI Metrics */}
      <Grid mb="lg">
        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Inbox Events Received
            </Text>
            <Text fz="xl" fw={700} c="white" mt={4}>
              {stats?.totalReceived ?? '--'}
            </Text>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Successfully Processed
            </Text>
            <Text fz="xl" fw={700} c="teal.4" mt={4}>
              {stats?.processed ?? '--'}
            </Text>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Skipped / Duplicates
            </Text>
            <Text fz="xl" fw={700} c="yellow.4" mt={4}>
              {(stats?.duplicate ?? 0) + (stats?.skipped ?? 0)}
            </Text>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              KMS Parity Status
            </Text>
            <Box mt={6}>
              {reconciliation?.synchronized ? (
                <Badge color="teal" size="lg" variant="light">
                  100% SYNCHRONIZED
                </Badge>
              ) : reconciliation ? (
                <Badge color="red" size="lg" variant="light">
                  {reconciliation.missingCount} MISSING
                </Badge>
              ) : (
                <Badge color="gray" size="lg" variant="light">
                  UNKNOWN
                </Badge>
              )}
            </Box>
          </Card>
        </Grid.Col>
      </Grid>

      {/* Reconciliation Report Banner */}
      {reconciliation && (
        <Alert
          icon={reconciliation.synchronized ? <IconShieldCheck size={20} /> : <IconAlertTriangle size={20} />}
          color={reconciliation.synchronized ? 'teal' : 'red'}
          title={
            reconciliation.synchronized
              ? 'Complete Synchronization Verified with KMS'
              : 'Reconciliation Discrepancy Detected'
          }
          radius="md"
          mb="lg"
        >
          <Group justify="space-between" align="center" wrap="wrap">
            <Text fz="sm">
              {reconciliation.synchronized
                ? `All ${reconciliation.kmsTotal} KMS certificates exist in the Responder database with matching statuses.`
                : `${reconciliation.missingCount} certificates are missing in Responder, and ${reconciliation.mismatchCount} have mismatched statuses.`}
            </Text>
            <Text fz="xs" c="dimmed">
              Verified: {new Date(reconciliation.verifiedAt).toLocaleTimeString()} · KMS: {reconciliation.kmsTotal} · Responder: {reconciliation.responderTotal} · Matched: {reconciliation.matchedCount}
            </Text>
          </Group>
        </Alert>
      )}

      {/* Search & Filter */}
      <Paper p="sm" radius="md" mb="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
        <Group>
          <TextInput
            placeholder="Filter by certificate serial hex..."
            leftSection={<IconSearch size={16} />}
            value={searchSerial}
            onChange={(e) => setSearchSerial(e.currentTarget.value)}
            style={{ flex: 1 }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') loadData()
            }}
          />
          <Button variant="default" onClick={loadData}>
            Apply Filter
          </Button>
          {searchSerial && (
            <Button
              variant="subtle"
              color="gray"
              onClick={() => {
                setSearchSerial('')
                setTimeout(loadData, 50)
              }}
            >
              Clear
            </Button>
          )}
        </Group>
      </Paper>

      {/* Inbox Events Table */}
      <Paper radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)', overflow: 'hidden' }}>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)' }}>
            <Table.Tr>
              <Table.Th>Event ID</Table.Th>
              <Table.Th>Certificate Serial</Table.Th>
              <Table.Th>Status / Reason</Table.Th>
              <Table.Th>Seq</Table.Th>
              <Table.Th>Received Time</Table.Th>
              <Table.Th>Processing State</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {loading ? (
              <Table.Tr>
                <Table.Td colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                  <Group justify="center" gap="sm">
                    <Loader size="sm" color="indigo" />
                    <Text fz="sm" c="dimmed">Loading inbox events...</Text>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ) : events.length === 0 ? (
              <Table.Tr>
                <Table.Td colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                  <Text fz="sm" c="dimmed">No inbox events found.</Text>
                </Table.Td>
              </Table.Tr>
            ) : (
              events.map((e) => {
                const isGood = e.status === 'GOOD'
                const isHold = e.revocationReason === 'CERTIFICATE_HOLD'
                const serialShort =
                  e.certificateSerial.length > 16
                    ? `${e.certificateSerial.slice(0, 8)}...${e.certificateSerial.slice(-8)}`
                    : e.certificateSerial

                const statusColor =
                  e.processingStatus === 'PROCESSED'
                    ? 'teal'
                    : e.processingStatus === 'DUPLICATE' || e.processingStatus === 'SKIPPED'
                    ? 'yellow'
                    : 'red'

                return (
                  <Table.Tr key={e.eventId}>
                    <Table.Td>
                      <Group gap={4}>
                        <Text ff="monospace" fz="xs" c="indigo.3">
                          {e.eventId.slice(0, 8)}...
                        </Text>
                        <CopyButton value={e.eventId}>
                          {({ copied, copy }) => (
                            <Tooltip label={copied ? 'Copied' : 'Copy Event ID'}>
                              <ActionIcon size="xs" variant="subtle" onClick={copy}>
                                {copied ? <IconCheck size={12} color="teal" /> : <IconCopy size={12} />}
                              </ActionIcon>
                            </Tooltip>
                          )}
                        </CopyButton>
                      </Group>
                    </Table.Td>

                    <Table.Td>
                      <Group gap={4}>
                        <Text ff="monospace" fz="xs" c="dimmed">
                          {serialShort}
                        </Text>
                        <CopyButton value={e.certificateSerial}>
                          {({ copied, copy }) => (
                            <Tooltip label={copied ? 'Copied' : 'Copy Serial Hex'}>
                              <ActionIcon size="xs" variant="subtle" onClick={copy}>
                                {copied ? <IconCheck size={12} color="teal" /> : <IconCopy size={12} />}
                              </ActionIcon>
                            </Tooltip>
                          )}
                        </CopyButton>
                      </Group>
                    </Table.Td>

                    <Table.Td>
                      <Group gap={6}>
                        {isGood ? (
                          <Badge color="teal" size="sm" variant="light">
                            GOOD
                          </Badge>
                        ) : isHold ? (
                          <Badge color="yellow" size="sm" variant="light">
                            ON HOLD
                          </Badge>
                        ) : (
                          <Badge color="red" size="sm" variant="light">
                            REVOKED
                          </Badge>
                        )}
                        {e.revocationReason && (
                          <Text fz="xs" c="dimmed">
                            {e.revocationReason}
                          </Text>
                        )}
                      </Group>
                    </Table.Td>

                    <Table.Td>
                      <Badge variant="outline" color="gray" size="sm">
                        v{e.sequence}
                      </Badge>
                    </Table.Td>

                    <Table.Td>
                      <Text fz="xs" c="dimmed">
                        {e.receivedAt ? new Date(e.receivedAt).toLocaleTimeString() : '--'}
                      </Text>
                    </Table.Td>

                    <Table.Td>
                      <Badge color={statusColor} size="sm">
                        {e.processingStatus}
                      </Badge>
                      {e.errorMessage && (
                        <Text fz="10px" c="red" mt={2}>
                          {e.errorMessage}
                        </Text>
                      )}
                    </Table.Td>
                  </Table.Tr>
                )
              })
            )}
          </Table.Tbody>
        </Table>
      </Paper>
    </Box>
  )
}
