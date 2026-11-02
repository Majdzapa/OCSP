import { useState, useEffect, useCallback } from 'react'
import {
  Box, Typography, Card, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Chip,
  Alert, Pagination, Tooltip, Stack,
} from '@mui/material'
import {
  GppBadOutlined, GppGoodOutlined, PauseCircleOutlined, UndoOutlined,
} from '@mui/icons-material'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { getRevocationEvents } from '../api/client'
import type { RevocationEvent, Page } from '../types/api'

dayjs.extend(relativeTime)

const EVENT_META: Record<string, { label: string; color: 'error' | 'success' | 'warning' | 'info'; icon: React.ReactElement }> = {
  CertificateRevoked:   { label: 'Revoked',   color: 'error',   icon: <GppBadOutlined fontSize="small" /> },
  CertificateIssued:    { label: 'Issued',    color: 'success', icon: <GppGoodOutlined fontSize="small" /> },
  CertificateHeld:      { label: 'On Hold',   color: 'warning', icon: <PauseCircleOutlined fontSize="small" /> },
  CertificateUnrevoked: { label: 'Unrevoked', color: 'info',    icon: <UndoOutlined fontSize="small" /> },
}

export function RevocationFeed() {
  const [data, setData]       = useState<Page<RevocationEvent> | null>(null)
  const [page, setPage]       = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)

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

  useEffect(() => { load(page) }, [page, load])

  // Auto-refresh every 15s
  useEffect(() => {
    const id = setInterval(() => load(page), 15_000)
    return () => clearInterval(id)
  }, [page, load])

  const meta = (type: string) => EVENT_META[type] ?? { label: type, color: 'default' as const, icon: null }

  return (
    <Box className="page-enter">
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>Revocation Activity</Typography>
        <Typography variant="body2" sx={{ color: '#64748b', mt: 0.5 }}>
          Live feed of KMS certificate events — auto-refreshes every 15 s
        </Typography>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Card>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Event Type</TableCell>
                <TableCell>Serial Number</TableCell>
                <TableCell>Reason</TableCell>
                <TableCell>Revocation Time</TableCell>
                <TableCell>Received</TableCell>
                <TableCell>Sync Lag</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading
                ? Array.from({ length: 10 }).map((_, i) => (
                    <TableRow key={i}>
                      {Array.from({ length: 7 }).map((_, j) => (
                        <TableCell key={j}>
                          <Box sx={{ height: 14, background: 'rgba(255,255,255,0.05)', borderRadius: 1 }} />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                : (data?.content ?? []).map((ev) => {
                    const m = meta(ev.eventType)
                    const lag = ev.processedAt
                      ? dayjs(ev.processedAt).diff(dayjs(ev.receivedAt), 'ms')
                      : null
                    return (
                      <TableRow key={ev.eventId} hover>
                        <TableCell>
                          <Stack direction="row" spacing={0.5} alignItems="center">
                            <Box sx={{ color: `${m.color}.main`, display: 'flex' }}>{m.icon}</Box>
                            <Chip label={m.label} color={m.color} size="small" sx={{ fontSize: '0.68rem', height: 20 }} />
                          </Stack>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" sx={{ fontFamily: 'JetBrains Mono, monospace', color: '#a5b4fc' }}>
                            {ev.serialNumberHex.toUpperCase()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" sx={{ color: ev.revocationReason ? '#f59e0b' : '#475569' }}>
                            {ev.revocationReason ?? '—'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {ev.revocationTime ? dayjs(ev.revocationTime).format('DD/MM/YY HH:mm:ss') : '—'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={dayjs(ev.receivedAt).format('YYYY-MM-DD HH:mm:ss.SSS')}>
                            <Typography variant="caption">{dayjs(ev.receivedAt).fromNow()}</Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          {lag !== null ? (
                            <Chip
                              label={`${lag} ms`}
                              size="small"
                              color={lag < 60_000 ? 'success' : 'warning'}
                              sx={{ fontSize: '0.65rem', height: 20 }}
                            />
                          ) : '—'}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={ev.status}
                            size="small"
                            color={ev.status === 'PROCESSED' ? 'success' : ev.status === 'FAILED' ? 'error' : 'default'}
                            sx={{ fontSize: '0.65rem', height: 20 }}
                          />
                        </TableCell>
                      </TableRow>
                    )
                  })
              }
            </TableBody>
          </Table>
        </TableContainer>

        {data && data.totalPages > 1 && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
            <Pagination
              count={data.totalPages}
              page={page + 1}
              onChange={(_, v) => setPage(v - 1)}
              color="primary"
              size="small"
            />
          </Box>
        )}
      </Card>
    </Box>
  )
}
