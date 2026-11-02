import { useState, useEffect, useCallback } from 'react'
import {
  Box, Typography, Card, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow,
  Chip, IconButton, TextField, InputAdornment,
  Tooltip, CircularProgress, Alert, Pagination,
  Button,
} from '@mui/material'
import {
  SearchOutlined, DeleteOutlined, RefreshOutlined,
} from '@mui/icons-material'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { getCacheEntries, invalidateCacheEntry } from '../api/client'
import type { CacheEntry, Page } from '../types/api'

dayjs.extend(relativeTime)

export function CacheExplorer() {
  const [data, setData]         = useState<Page<CacheEntry> | null>(null)
  const [page, setPage]         = useState(0)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState<string | null>(null)
  const [search, setSearch]     = useState('')
  const [evicting, setEvicting] = useState<string | null>(null)

  const load = useCallback(async (p: number) => {
    setLoading(true)
    try {
      const result = await getCacheEntries(p, 20)
      setData(result)
      setError(null)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load cache')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(page) }, [page, load])

  const handleEvict = async (cacheKey: string) => {
    if (!window.confirm(`Invalidate cache entry\n${cacheKey}?`)) return
    setEvicting(cacheKey)
    try {
      await invalidateCacheEntry(cacheKey)
      await load(page)
    } catch (e: unknown) {
      alert('Invalidation failed: ' + (e instanceof Error ? e.message : 'unknown error'))
    } finally {
      setEvicting(null)
    }
  }

  const isExpired = (nextUpdate: string) => dayjs(nextUpdate).isBefore(dayjs())
  const expiresIn = (nextUpdate: string) => dayjs(nextUpdate).fromNow()

  return (
    <Box className="page-enter">
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h5" fontWeight={700}>Cache Explorer</Typography>
          <Typography variant="body2" sx={{ color: '#64748b', mt: 0.5 }}>
            Inspect and manually invalidate L2 cached OCSP responses
          </Typography>
        </Box>
        <Button
          startIcon={<RefreshOutlined />}
          onClick={() => load(page)}
          variant="outlined"
          size="small"
          sx={{ borderColor: 'rgba(255,255,255,0.12)' }}
        >
          Refresh
        </Button>
      </Box>

      {/* Search bar */}
      <TextField
        fullWidth
        placeholder="Search by cache key or serial hex…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        size="small"
        sx={{ mb: 2 }}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <SearchOutlined sx={{ color: '#64748b', fontSize: 18 }} />
            </InputAdornment>
          ),
          sx: {
            background: 'rgba(255,255,255,0.03)',
            borderRadius: '10px',
            '& fieldset': { borderColor: 'rgba(255,255,255,0.08)' },
          },
        }}
      />

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Card>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Cache Key (SHA-1)</TableCell>
                <TableCell>This Update</TableCell>
                <TableCell>Next Update</TableCell>
                <TableCell>Size</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading
                ? Array.from({ length: 8 }).map((_, i) => (
                    <TableRow key={i}>
                      {Array.from({ length: 6 }).map((_, j) => (
                        <TableCell key={j}><Box sx={{ height: 16, background: 'rgba(255,255,255,0.05)', borderRadius: 1 }} /></TableCell>
                      ))}
                    </TableRow>
                  ))
                : (data?.content ?? [])
                    .filter((e) => !search || e.cacheKey.includes(search))
                    .map((entry) => (
                      <TableRow key={entry.cacheKey} hover>
                        <TableCell>
                          <Typography variant="caption" sx={{ fontFamily: 'JetBrains Mono, monospace', color: '#a5b4fc' }}>
                            {entry.cacheKey}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {dayjs(entry.thisUpdate).format('HH:mm:ss DD/MM/YY')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={dayjs(entry.nextUpdate).format('YYYY-MM-DD HH:mm:ss')}>
                            <Typography variant="caption">{expiresIn(entry.nextUpdate)}</Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{entry.responseSizeBytes} B</Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={isExpired(entry.nextUpdate) ? 'Expired' : 'Valid'}
                            size="small"
                            color={isExpired(entry.nextUpdate) ? 'warning' : 'success'}
                            sx={{ fontSize: '0.65rem', height: 20 }}
                          />
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="Manually invalidate this cache entry">
                            <IconButton
                              size="small"
                              onClick={() => handleEvict(entry.cacheKey)}
                              disabled={evicting === entry.cacheKey}
                              sx={{ color: '#f43f5e', '&:hover': { background: 'rgba(244,63,94,0.1)' } }}
                            >
                              {evicting === entry.cacheKey
                                ? <CircularProgress size={14} color="error" />
                                : <DeleteOutlined fontSize="small" />
                              }
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))
              }
            </TableBody>
          </Table>
        </TableContainer>

        {/* Pagination */}
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
