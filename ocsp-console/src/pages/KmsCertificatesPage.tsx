import React, { useState, useEffect, useMemo } from 'react'
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  InputAdornment,
  Button,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress,
  Alert,
  Tooltip,
  Paper,
} from '@mui/material'
import {
  SearchOutlined,
  RefreshOutlined,
  KeyOutlined,
  CheckCircleOutlined,
  CancelOutlined,
  PauseCircleOutlined,
  PlayArrowOutlined,
  ContentCopyOutlined,
  DownloadOutlined,
  VisibilityOutlined,
  WarningAmberOutlined,
  CloseOutlined,
  FilterListOutlined,
} from '@mui/icons-material'
import {
  getKmsCertificates,
  revokeKmsCertificate,
  unrevokeKmsCertificate,
  triggerKmsRevocationJob,
} from '../api/client'
import type { KmsCertificate, KmsRevocationReason } from '../types/api'

// ---------------------------------------------------------------------------
// RFC 5280 Reasons Metadata
// ---------------------------------------------------------------------------
const RFC_5280_REASONS: { code: KmsRevocationReason; label: string; description: string }[] = [
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
    description: 'Subject name, organizational affiliation, or identity changed',
  },
  {
    code: 'SUPERSEDED',
    label: 'Superseded (4)',
    description: 'Certificate was replaced by a new certificate',
  },
  {
    code: 'CESSATION_OF_OPERATION',
    label: 'Cessation of Operation (5)',
    description: 'Server, domain, or service has permanently ceased operation',
  },
  {
    code: 'CERTIFICATE_HOLD',
    label: 'Certificate Hold / Suspension (6)',
    description: 'Temporary suspension — can be un-revoked / reinstated back to GOOD later',
  },
  {
    code: 'PRIVILEGE_WITHDRAWN',
    label: 'Privilege Withdrawn (9)',
    description: 'Subject privileges, credentials, or certifications were revoked',
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
  const [alert, setAlert] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null)

  // Filters
  const [search, setSearch] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'GOOD' | 'REVOKED' | 'HOLD'>('ALL')

  // Pagination
  const [page, setPage] = useState<number>(0)
  const [rowsPerPage, setRowsPerPage] = useState<number>(10)

  // Revoke Dialog
  const [revokeDialogOpen, setRevokeDialogOpen] = useState<boolean>(false)
  const [targetCert, setTargetCert] = useState<KmsCertificate | null>(null)
  const [revokeReason, setRevokeReason] = useState<string>('KEY_COMPROMISE')
  const [actionLoading, setActionLoading] = useState<boolean>(false)

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
      setError(err?.response?.data?.message || err?.message || 'Failed to load KMS certificates')
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
        const daysLeft = (notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
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
      // Status filter
      if (statusFilter === 'GOOD' && c.status !== 'GOOD') return false
      if (statusFilter === 'REVOKED' && c.status !== 'REVOKED') return false
      if (statusFilter === 'HOLD' && !(c.status === 'REVOKED' && c.revocationReason === 'CERTIFICATE_HOLD')) return false

      // Search term
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
        type: 'success',
        message: `Certificate ${truncateSerial(targetCert.serialNumberHex)} revoked (${revokeReason}). Event published to RabbitMQ!`,
      })
      setRevokeDialogOpen(false)
      fetchCertificates()
    } catch (err: any) {
      setAlert({
        type: 'error',
        message: err?.response?.data?.error || err?.message || 'Revocation failed',
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
        type: 'success',
        message: `Certificate ${truncateSerial(cert.serialNumberHex)} hold released. Reinstated to GOOD!`,
      })
      fetchCertificates()
    } catch (err: any) {
      setAlert({
        type: 'error',
        message: err?.response?.data?.error || err?.message || 'Un-revocation failed',
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
        type: 'info',
        message: 'KMS Simulator job executed: random GOOD certs revoked / HOLD certs unrevoked. RabbitMQ events published.',
      })
      // Give RabbitMQ / DB 500ms to process
      setTimeout(() => {
        fetchCertificates()
        setJobTriggerLoading(false)
      }, 500)
    } catch (err: any) {
      setAlert({
        type: 'error',
        message: err?.response?.data?.error || err?.message || 'Failed to trigger revocation job',
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

  return (
    <Box className="page-enter">
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <KeyOutlined sx={{ color: '#818cf8', fontSize: 32 }} />
            <Typography variant="h5" fontWeight={700}>
              KMS Certificate Manager
            </Typography>
          </Box>
          <Typography variant="body2" sx={{ color: '#94a3b8', mt: 0.5 }}>
            Source of truth certificate inventory — Incert Test PKI simulation with Transactional Outbox event publishing
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshOutlined />}
            onClick={fetchCertificates}
            disabled={loading}
            sx={{ borderColor: 'rgba(255,255,255,0.12)' }}
          >
            Refresh
          </Button>

          <Button
            variant="contained"
            color="primary"
            startIcon={jobTriggerLoading ? <CircularProgress size={16} color="inherit" /> : <PlayArrowOutlined />}
            onClick={handleTriggerJob}
            disabled={jobTriggerLoading}
            sx={{
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              fontWeight: 600,
            }}
          >
            Run Revocation Job
          </Button>
        </Box>
      </Box>

      {/* Notifications / Alerts */}
      {alert && (
        <Alert
          severity={alert.type}
          onClose={() => setAlert(null)}
          sx={{ mb: 3, border: '1px solid rgba(255,255,255,0.08)' }}
        >
          {alert.message}
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Metrics Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
              <Typography variant="caption" sx={{ color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Total Certs
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, mt: 0.5, color: '#e2e8f0' }}>
                {metrics.total}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
              <Typography variant="caption" sx={{ color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Good / Active
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, mt: 0.5, color: '#22c55e' }}>
                {metrics.good}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
              <Typography variant="caption" sx={{ color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Revoked (Total)
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, mt: 0.5, color: '#f43f5e' }}>
                {metrics.revoked}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
              <Typography variant="caption" sx={{ color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                On Hold (Suspended)
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, mt: 0.5, color: '#f59e0b' }}>
                {metrics.hold}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
              <Typography variant="caption" sx={{ color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Near Expiry (&le;30d)
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, mt: 0.5, color: '#38bdf8' }}>
                {metrics.expiredSoon}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filter and Search Bar */}
      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search by Serial Hex or Subject DN..."
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value)
                  setPage(0)
                }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchOutlined sx={{ color: '#64748b' }} />
                    </InputAdornment>
                  ),
                  endAdornment: search ? (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => setSearch('')}>
                        <CloseOutlined sx={{ fontSize: 16 }} />
                      </IconButton>
                    </InputAdornment>
                  ) : null,
                }}
              />
            </Grid>

            <Grid item xs={12} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel id="status-filter-label">Filter Status</InputLabel>
                <Select
                  labelId="status-filter-label"
                  label="Filter Status"
                  value={statusFilter}
                  onChange={(e) => {
                    setStatusFilter(e.target.value as any)
                    setPage(0)
                  }}
                  startAdornment={
                    <InputAdornment position="start">
                      <FilterListOutlined sx={{ color: '#64748b', fontSize: 18 }} />
                    </InputAdornment>
                  }
                >
                  <MenuItem value="ALL">All Certificates ({metrics.total})</MenuItem>
                  <MenuItem value="GOOD">Good / Active ({metrics.good})</MenuItem>
                  <MenuItem value="REVOKED">Revoked ({metrics.revoked})</MenuItem>
                  <MenuItem value="HOLD">On Hold / Suspended ({metrics.hold})</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={2} sx={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Typography variant="caption" sx={{ color: '#64748b' }}>
                Showing {filteredCerts.length} of {certificates.length}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Certificates Table */}
      <Card>
        <TableContainer>
          <Table size="medium">
            <TableHead>
              <TableRow sx={{ background: 'rgba(255,255,255,0.02)' }}>
                <TableCell sx={{ fontWeight: 600, color: '#94a3b8' }}>Serial Number</TableCell>
                <TableCell sx={{ fontWeight: 600, color: '#94a3b8' }}>Subject DN</TableCell>
                <TableCell sx={{ fontWeight: 600, color: '#94a3b8' }}>Validity Window</TableCell>
                <TableCell sx={{ fontWeight: 600, color: '#94a3b8' }}>Status / Reason</TableCell>
                <TableCell sx={{ fontWeight: 600, color: '#94a3b8', width: 80 }}>Seq</TableCell>
                <TableCell sx={{ fontWeight: 600, color: '#94a3b8', textAlign: 'right' }}>Actions</TableCell>
              </TableRow>
            </TableHead>

            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 6 }}>
                    <CircularProgress size={32} />
                    <Typography variant="body2" sx={{ color: '#94a3b8', mt: 2 }}>
                      Loading certificate inventory...
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : filteredCerts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 6 }}>
                    <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                      No certificates match the selected filter or search term.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                filteredCerts
                  .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                  .map((cert) => {
                    const isGood = cert.status === 'GOOD'
                    const isHold = cert.status === 'REVOKED' && cert.revocationReason === 'CERTIFICATE_HOLD'

                    // Expiration calculation
                    let expiryBadge: React.ReactNode = null
                    try {
                      const notAfter = new Date(cert.notAfter)
                      const diffDays = Math.ceil((notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
                      if (diffDays < 0) {
                        expiryBadge = (
                          <Chip
                            label={`Expired ${Math.abs(diffDays)}d ago`}
                            size="small"
                            sx={{ bgcolor: 'rgba(244,63,94,0.12)', color: '#f43f5e', fontSize: '0.68rem', height: 18 }}
                          />
                        )
                      } else if (diffDays <= 30) {
                        expiryBadge = (
                          <Chip
                            label={`Expiring in ${diffDays}d`}
                            size="small"
                            sx={{ bgcolor: 'rgba(245,158,11,0.12)', color: '#f59e0b', fontSize: '0.68rem', height: 18 }}
                          />
                        )
                      }
                    } catch {
                      /* ignore */
                    }

                    return (
                      <TableRow
                        key={cert.serialNumberHex}
                        hover
                        sx={{
                          '&:last-child td, &:last-child th': { border: 0 },
                          transition: 'background 0.15s ease',
                        }}
                      >
                        {/* Serial */}
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Tooltip title={cert.serialNumberHex} arrow placement="top">
                              <Typography
                                variant="caption"
                                sx={{
                                  fontFamily: "'JetBrains Mono', monospace",
                                  fontWeight: 600,
                                  color: '#e2e8f0',
                                  cursor: 'pointer',
                                }}
                                onClick={() => openDetailsModal(cert)}
                              >
                                {truncateSerial(cert.serialNumberHex)}
                              </Typography>
                            </Tooltip>
                            <Tooltip title="Copy full serial hex">
                              <IconButton
                                size="small"
                                onClick={() => {
                                  copyToClipboard(cert.serialNumberHex, () => {
                                    setCopiedSerial(cert.serialNumberHex)
                                    setTimeout(() => setCopiedSerial(null), 1500)
                                  })
                                }}
                              >
                                <ContentCopyOutlined sx={{ fontSize: 14, color: copiedSerial === cert.serialNumberHex ? '#22c55e' : '#64748b' }} />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>

                        {/* Subject DN */}
                        <TableCell>
                          <Typography variant="body2" sx={{ fontWeight: 500, color: '#e2e8f0' }}>
                            {cert.subjectDn}
                          </Typography>
                          <Typography variant="caption" sx={{ color: '#64748b', display: 'block' }}>
                            Issuer: {cert.issuerDn}
                          </Typography>
                        </TableCell>

                        {/* Validity */}
                        <TableCell>
                          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.4 }}>
                            <Typography variant="caption" sx={{ color: '#94a3b8' }}>
                              {formatDate(cert.notBefore)} &rarr; {formatDate(cert.notAfter)}
                            </Typography>
                            {expiryBadge}
                          </Box>
                        </TableCell>

                        {/* Status */}
                        <TableCell>
                          {isGood ? (
                            <Chip
                              icon={<CheckCircleOutlined sx={{ fontSize: '14px !important' }} />}
                              label="GOOD"
                              size="small"
                              sx={{
                                fontWeight: 700,
                                fontSize: '0.75rem',
                                color: '#22c55e',
                                bgcolor: 'rgba(34,197,94,0.12)',
                                border: '1px solid rgba(34,197,94,0.3)',
                              }}
                            />
                          ) : isHold ? (
                            <Tooltip title="Certificate is temporarily on hold. Click 'Release Hold' to reinstate.">
                              <Chip
                                icon={<PauseCircleOutlined sx={{ fontSize: '14px !important' }} />}
                                label="ON HOLD (Suspended)"
                                size="small"
                                sx={{
                                  fontWeight: 700,
                                  fontSize: '0.75rem',
                                  color: '#f59e0b',
                                  bgcolor: 'rgba(245,158,11,0.12)',
                                  border: '1px solid rgba(245,158,11,0.3)',
                                }}
                              />
                            </Tooltip>
                          ) : (
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.25 }}>
                              <Chip
                                icon={<CancelOutlined sx={{ fontSize: '14px !important' }} />}
                                label={`REVOKED`}
                                size="small"
                                sx={{
                                  fontWeight: 700,
                                  fontSize: '0.75rem',
                                  color: '#f43f5e',
                                  bgcolor: 'rgba(244,63,94,0.12)',
                                  border: '1px solid rgba(244,63,94,0.3)',
                                  width: 'fit-content',
                                }}
                              />
                              <Typography variant="caption" sx={{ color: '#f43f5e', fontSize: '0.68rem' }}>
                                Reason: {cert.revocationReason || 'UNSPECIFIED'}
                              </Typography>
                            </Box>
                          )}
                        </TableCell>

                        {/* Sequence */}
                        <TableCell>
                          <Typography
                            variant="caption"
                            sx={{
                              fontFamily: "'JetBrains Mono', monospace",
                              bgcolor: 'rgba(255,255,255,0.06)',
                              px: 1,
                              py: 0.3,
                              borderRadius: '4px',
                            }}
                          >
                            v{cert.sequence}
                          </Typography>
                        </TableCell>

                        {/* Actions */}
                        <TableCell align="right">
                          <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                            {isGood && (
                              <Button
                                size="small"
                                variant="outlined"
                                color="error"
                                onClick={() => openRevokeModal(cert)}
                                sx={{
                                  textTransform: 'none',
                                  fontSize: '0.75rem',
                                  py: 0.4,
                                  px: 1.2,
                                  borderColor: 'rgba(244,63,94,0.4)',
                                  '&:hover': { bgcolor: 'rgba(244,63,94,0.08)' },
                                }}
                              >
                                Revoke
                              </Button>
                            )}

                            {isHold && (
                              <Button
                                size="small"
                                variant="contained"
                                color="warning"
                                disabled={actionLoading}
                                onClick={() => handleUnrevoke(cert)}
                                sx={{
                                  textTransform: 'none',
                                  fontSize: '0.75rem',
                                  py: 0.4,
                                  px: 1.2,
                                  fontWeight: 600,
                                }}
                              >
                                Release Hold
                              </Button>
                            )}

                            <Tooltip title="View Certificate Details & PEM">
                              <IconButton
                                size="small"
                                onClick={() => openDetailsModal(cert)}
                                sx={{ color: '#818cf8', bgcolor: 'rgba(99,102,241,0.08)' }}
                              >
                                <VisibilityOutlined sx={{ fontSize: 16 }} />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    )
                  })
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <TablePagination
          rowsPerPageOptions={[10, 25, 50]}
          component="div"
          count={filteredCerts.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10))
            setPage(0)
          }}
          sx={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
        />
      </Card>

      {/* =================================================================== */}
      {/* Revocation Dialog                                                  */}
      {/* =================================================================== */}
      <Dialog
        open={revokeDialogOpen}
        onClose={() => !actionLoading && setRevokeDialogOpen(false)}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            bgcolor: '#0f1629',
            border: '1px solid rgba(255,255,255,0.1)',
            backgroundImage: 'none',
          },
        }}
      >
        <DialogTitle sx={{ fontWeight: 700, pb: 1 }}>
          Revoke Certificate
        </DialogTitle>

        <DialogContent dividers sx={{ borderColor: 'rgba(255,255,255,0.08)' }}>
          {targetCert && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
              <Box sx={{ p: 1.5, bgcolor: 'rgba(255,255,255,0.03)', borderRadius: 2 }}>
                <Typography variant="caption" sx={{ color: '#94a3b8', display: 'block' }}>
                  Target Certificate
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 600, color: '#e2e8f0', mt: 0.3 }}>
                  {targetCert.subjectDn}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#818cf8', display: 'block', mt: 0.5 }}
                >
                  Serial: {targetCert.serialNumberHex}
                </Typography>
              </Box>

              <FormControl fullWidth>
                <InputLabel id="revocation-reason-select-label">Revocation Reason (RFC 5280)</InputLabel>
                <Select
                  labelId="revocation-reason-select-label"
                  label="Revocation Reason (RFC 5280)"
                  value={revokeReason}
                  onChange={(e) => setRevokeReason(e.target.value)}
                >
                  {RFC_5280_REASONS.map((r) => (
                    <MenuItem key={r.code} value={r.code}>
                      <Box>
                        <Typography variant="body2" fontWeight={600}>
                          {r.label}
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#94a3b8' }}>
                          {r.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Alert severity="warning" icon={<WarningAmberOutlined />} sx={{ mt: 1 }}>
                Revoking immediately creates a Transactional Outbox record in the KMS database and relays a{' '}
                <code>CertificateStatusChanged</code> event to RabbitMQ exchange <code>incert.certificate.status</code>.
                The OCSP responder will update its state and invalidate cached responses.
              </Alert>
            </Box>
          )}
        </DialogContent>

        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button
            onClick={() => setRevokeDialogOpen(false)}
            disabled={actionLoading}
            sx={{ color: '#94a3b8' }}
          >
            Cancel
          </Button>

          <Button
            variant="contained"
            color="error"
            onClick={handleConfirmRevoke}
            disabled={actionLoading}
            startIcon={actionLoading ? <CircularProgress size={16} color="inherit" /> : <CancelOutlined />}
            sx={{ fontWeight: 600 }}
          >
            Confirm Revocation
          </Button>
        </DialogActions>
      </Dialog>

      {/* =================================================================== */}
      {/* Details & PEM Dialog                                               */}
      {/* =================================================================== */}
      <Dialog
        open={detailsDialogOpen}
        onClose={() => setDetailsDialogOpen(false)}
        maxWidth="md"
        fullWidth
        PaperProps={{
          sx: {
            bgcolor: '#0f1629',
            border: '1px solid rgba(255,255,255,0.1)',
            backgroundImage: 'none',
          },
        }}
      >
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <KeyOutlined sx={{ color: '#818cf8' }} />
            <Typography variant="h6" fontWeight={700}>
              Certificate Details & PEM
            </Typography>
          </Box>
          <IconButton size="small" onClick={() => setDetailsDialogOpen(false)}>
            <CloseOutlined />
          </IconButton>
        </DialogTitle>

        <DialogContent dividers sx={{ borderColor: 'rgba(255,255,255,0.08)' }}>
          {detailsCert && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {/* Metadata Table */}
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#818cf8', mb: 1.5 }}>
                  X.509 ATTRIBUTES
                </Typography>

                <Paper sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <Grid container spacing={1.5}>
                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Serial Number</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="caption" sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#e2e8f0', wordBreak: 'break-all' }}>
                        {detailsCert.serialNumberHex}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Subject DN</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="body2" sx={{ color: '#e2e8f0', fontWeight: 500 }}>
                        {detailsCert.subjectDn}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Issuer DN</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="body2" sx={{ color: '#e2e8f0' }}>
                        {detailsCert.issuerDn}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Issuer Key Hash (SHA-1)</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="caption" sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#94a3b8' }}>
                        {detailsCert.issuerKeyHashHex}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Issuer Name Hash (SHA-1)</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="caption" sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#94a3b8' }}>
                        {detailsCert.issuerNameHashHex}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Validity Period</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="caption" sx={{ color: '#e2e8f0' }}>
                        {formatDate(detailsCert.notBefore)} &mdash; {formatDate(detailsCert.notAfter)}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Status</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Chip
                          label={detailsCert.status}
                          size="small"
                          color={detailsCert.status === 'GOOD' ? 'success' : 'error'}
                          sx={{ fontWeight: 700, height: 20 }}
                        />
                        {detailsCert.status === 'REVOKED' && (
                          <Typography variant="caption" sx={{ color: '#f43f5e' }}>
                            Reason: {detailsCert.revocationReason} ({formatDate(detailsCert.revocationTime)})
                          </Typography>
                        )}
                      </Box>
                    </Grid>

                    <Grid item xs={12} sm={3}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Sequence</Typography>
                    </Grid>
                    <Grid item xs={12} sm={9}>
                      <Typography variant="caption" sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#818cf8' }}>
                        v{detailsCert.sequence}
                      </Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </Box>

              {/* PEM Block */}
              <Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#818cf8' }}>
                    PEM CERTIFICATE
                  </Typography>

                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button
                      size="small"
                      startIcon={<ContentCopyOutlined />}
                      onClick={() => {
                        copyToClipboard(detailsCert.pemEncoded, () => {
                          setCopiedPem(true)
                          setTimeout(() => setCopiedPem(false), 2000)
                        })
                      }}
                      sx={{ textTransform: 'none', color: copiedPem ? '#22c55e' : '#818cf8' }}
                    >
                      {copiedPem ? 'Copied!' : 'Copy PEM'}
                    </Button>

                    <Button
                      size="small"
                      startIcon={<DownloadOutlined />}
                      onClick={() => downloadPem(detailsCert.pemEncoded, `cert-${truncateSerial(detailsCert.serialNumberHex)}.crt`)}
                      sx={{ textTransform: 'none', color: '#818cf8' }}
                    >
                      Download .crt
                    </Button>
                  </Box>
                </Box>

                <Paper
                  sx={{
                    p: 2,
                    bgcolor: '#080c14',
                    border: '1px solid rgba(255,255,255,0.06)',
                    maxHeight: 220,
                    overflowY: 'auto',
                  }}
                >
                  <Typography
                    variant="caption"
                    component="pre"
                    sx={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '0.72rem',
                      color: '#a5b4fc',
                      margin: 0,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}
                  >
                    {detailsCert.pemEncoded}
                  </Typography>
                </Paper>
              </Box>
            </Box>
          )}
        </DialogContent>

        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button onClick={() => setDetailsDialogOpen(false)} sx={{ color: '#94a3b8' }}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}
