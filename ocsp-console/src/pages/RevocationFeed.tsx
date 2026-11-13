import { useState, useEffect, useCallback } from 'react'
import {
  Box,
  Text,
  Title,
  Card,
  Table,
  Badge,
  Alert,
  Pagination,
  Tooltip,
  Group,
  Skeleton,
} from '@mantine/core'
import {
  IconShieldX,
  IconShieldCheck,
  IconPlayerPause,
  IconArrowBackUp,
  IconAlertCircle,
} from '@tabler/icons-react'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { getRevocationEvents } from '../api/client'
import type { RevocationEvent, Page } from '../types/api'

dayjs.extend(relativeTime)

const EVENT_META: Record<
  string,
  { label: string; color: string; icon: React.ReactElement }
> = {
  CertificateRevoked: {
    label: 'Revoked',
    color: 'red',
    icon: <IconShieldX size={14} />,
  },
  CertificateIssued: {
    label: 'Issued',
    color: 'teal',
    icon: <IconShieldCheck size={14} />,
  },
  CertificateHeld: {
    label: 'On Hold',
    color: 'yellow',
    icon: <IconPlayerPause size={14} />,
  },
  CertificateUnrevoked: {
    label: 'Unrevoked',
    color: 'blue',
    icon: <IconArrowBackUp size={14} />,
  },
}

export function RevocationFeed() {
  const [data, setData] = useState<Page<RevocationEvent> | null>(null)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async (p: number) => {
    setLoading(true)
    try {
      const result = await getRevocationEvents(p, 25)
      setData(result)
      setError(null)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load events')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(page)
  }, [page, load])

  // Auto-refresh every 15s
  useEffect(() => {
    const id = setInterval(() => load(page), 15_000)
    return () => clearInterval(id)
  }, [page, load])

  const meta = (type: string) =>
    EVENT_META[type] ?? { label: type, color: 'gray', icon: null }

  return (
    <Box className="page-enter">
      <Box mb="lg">
        <Title order={3} fw={700}>
          Revocation Activity
        </Title>
        <Text fz="sm" c="dimmed" mt={4}>
          Live feed of KMS certificate events — auto-refreshes every 15 s
        </Text>
      </Box>

      {error && (
        <Alert
          icon={<IconAlertCircle size={16} />}
          color="red"
          title="Error"
          mb="md"
        >
          {error}
        </Alert>
      )}

      <Card
        p="md"
        radius="md"
        style={{
          backgroundColor: 'var(--mantine-color-dark-6)',
          border: '1px solid var(--mantine-color-dark-4)',
        }}
      >
        <Table.ScrollContainer minWidth={750}>
          <Table verticalSpacing="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Event Type</Table.Th>
                <Table.Th>Serial Number</Table.Th>
                <Table.Th>Reason</Table.Th>
                <Table.Th>Revocation Time</Table.Th>
                <Table.Th>Received</Table.Th>
                <Table.Th>Sync Lag</Table.Th>
                <Table.Th>Status</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <Table.Tr key={i}>
                    {Array.from({ length: 7 }).map((_, j) => (
                      <Table.Td key={j}>
                        <Skeleton height={16} radius="sm" />
                      </Table.Td>
                    ))}
                  </Table.Tr>
                ))
              ) : (data?.content ?? []).length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={7}>
                    <Text ta="center" c="dimmed" py="xl">
                      No revocation events found.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                (data?.content ?? []).map((ev) => {
                  const eventType =
                    ev.eventType ||
                    (ev.revocationTime
                      ? 'CertificateRevoked'
                      : 'CertificateIssued')
                  const m = meta(eventType)
                  const serial = (
                    ev.serialNumberHex ||
                    ev.serialNumber ||
                    ''
                  ).toUpperCase()
                  const receivedAt =
                    ev.receivedAt ||
                    ev.thisUpdate ||
                    ev.updatedAt ||
                    new Date().toISOString()
                  const processedAt =
                    ev.processedAt || ev.thisUpdate || ev.updatedAt
                  const lag = processedAt
                    ? dayjs(processedAt).diff(dayjs(receivedAt), 'ms')
                    : null
                  const eventId = ev.eventId || serial || Math.random().toString()

                  return (
                    <Table.Tr key={eventId}>
                      <Table.Td>
                        <Group gap={6} wrap="nowrap">
                          <Badge
                            leftSection={m.icon}
                            color={m.color}
                            variant="light"
                            size="sm"
                          >
                            {m.label}
                          </Badge>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Text
                          fz="xs"
                          ff="'JetBrains Mono', monospace"
                          c="indigo.3"
                        >
                          {serial || '—'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text
                          fz="xs"
                          c={ev.revocationReason ? 'yellow.5' : 'dimmed'}
                        >
                          {ev.revocationReason ?? '—'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text fz="xs">
                          {ev.revocationTime
                            ? dayjs(ev.revocationTime).format(
                                'DD/MM/YY HH:mm:ss'
                              )
                            : '—'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Tooltip
                          label={dayjs(receivedAt).format(
                            'YYYY-MM-DD HH:mm:ss.SSS'
                          )}
                          withArrow
                        >
                          <Text fz="xs" style={{ cursor: 'pointer' }}>
                            {dayjs(receivedAt).fromNow()}
                          </Text>
                        </Tooltip>
                      </Table.Td>
                      <Table.Td>
                        {lag !== null ? (
                          <Badge
                            color={lag < 60_000 ? 'teal' : 'yellow'}
                            variant="light"
                            size="sm"
                          >
                            {lag} ms
                          </Badge>
                        ) : (
                          <Text fz="xs" c="dimmed">
                            —
                          </Text>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Badge
                          color={ev.status === 'FAILED' ? 'red' : 'teal'}
                          variant="light"
                          size="sm"
                        >
                          {ev.status || 'PROCESSED'}
                        </Badge>
                      </Table.Td>
                    </Table.Tr>
                  )
                })
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>

        {data && data.totalPages > 1 && (
          <Group justify="center" mt="md" py="xs">
            <Pagination
              total={data.totalPages}
              value={page + 1}
              onChange={(v) => setPage(v - 1)}
              color="indigo"
              size="sm"
            />
          </Group>
        )}
      </Card>
    </Box>
  )
}
