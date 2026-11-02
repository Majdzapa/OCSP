import { useState } from 'react'
import {
  Box, Typography, Card, CardContent, TextField, InputAdornment,
  Button, CircularProgress, Chip, Alert, Divider, Collapse,
  Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions,
} from '@mui/material'
import {
  SearchOutlined,
  CheckCircleOutlined,
  CancelOutlined,
  HelpOutlineOutlined,
  AutorenewOutlined,
  ContentCopyOutlined,
  KeyOutlined,
} from '@mui/icons-material'
import { checkCertStatus, requestCertRenewal } from '../api/client'
import type { CertStatusResponse, RenewRequestResponse } from '../types/api'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function StatusChip({ status }: { status: CertStatusResponse['status'] }) {
  const map = {
    GOOD:    { label: 'GOOD',    color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  icon: <CheckCircleOutlined sx={{ fontSize: 14 }} /> },
    REVOKED: { label: 'REVOKED', color: '#f43f5e', bg: 'rgba(244,63,94,0.12)', icon: <CancelOutlined     sx={{ fontSize: 14 }} /> },
    UNKNOWN: { label: 'UNKNOWN', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',icon: <HelpOutlineOutlined sx={{ fontSize: 14 }} /> },
  }
  const { label, color, bg, icon } = map[status]
  return (
    <Chip
      icon={icon}
      label={label}
      size="medium"
      sx={{
        fontWeight: 700, fontSize: '0.85rem', letterSpacing: 1,
        color, bgcolor: bg, border: `1px solid ${color}40`,
        '& .MuiChip-icon': { color },
      }}
    />
  )
}

function Row({ label, value, mono = false }: { label: string; value: string | null; mono?: boolean }) {
  if (value === null) return null
  return (
    <Box sx={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
      py: 0.85, borderBottom: '1px solid rgba(255,255,255,0.05)',
      '&:last-child': { borderBottom: 'none' },
    }}>
      <Typography variant="body2" sx={{ color: '#64748b', minWidth: 160 }}>{label}</Typography>
      <Typography variant="body2" sx={{
        color: '#e2e8f0', textAlign: 'right', wordBreak: 'break-all',
        fontFamily: mono ? 'JetBrains Mono, monospace' : 'inherit', fontSize: mono ? '0.75rem' : '0.875rem',
      }}>
        {value}
      </Typography>
    </Box>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function CertCheckerPage() {
  const [serial, setSerial]   = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState<CertStatusResponse | null>(null)
  const [error, setError]     = useState<string | null>(null)

  // Renewal dialog
  const [renewOpen, setRenewOpen]     = useState(false)
  const [renewReason, setRenewReason] = useState('REVOKED — renewal requested via admin console')
  const [renewLoading, setRenewLoading] = useState(false)
  const [renewResult, setRenewResult]   = useState<RenewRequestResponse | null>(null)
  const [renewError, setRenewError]     = useState<string | null>(null)

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
      const msg = (e as { response?: { status?: number } }).response?.status === 400
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
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>Certificate Status Checker</Typography>
        <Typography variant="body2" sx={{ color: '#64748b', mt: 0.5 }}>
          Look up a certificate's OCSP status by serial number, then request renewal if revoked.
        </Typography>
      </Box>

      {/* Search card */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'flex-start' }}>
            <Box sx={{ flex: 1 }}>
              <TextField
                id="serial-input"
                fullWidth
                label="Certificate Serial Number (hex)"
                placeholder="e.g. 01ab23cd45ef"
                value={serial}
                onChange={(e) => setSerial(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <KeyOutlined sx={{ color: '#6366f1' }} />
                    </InputAdornment>
                  ),
                  sx: { fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem' },
                }}
                helperText="Enter the hex-encoded serial number of the certificate to check"
              />
            </Box>
            <Button
              id="check-cert-btn"
              variant="contained"
              onClick={handleCheck}
              disabled={loading || !serial.trim()}
              sx={{
                mt: 0.5, px: 3, py: 1.6, minWidth: 130,
                background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                '&:hover': { background: 'linear-gradient(135deg, #4f46e5, #7c3aed)' },
                '&:disabled': { opacity: 0.5 },
              }}
              startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <SearchOutlined />}
            >
              {loading ? 'Checking…' : 'Check Status'}
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Error state */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>
      )}

      {/* Result card */}
      <Collapse in={!!result}>
        {result && (
          <Card sx={{
            border: `1px solid ${
              result.status === 'GOOD'    ? 'rgba(34,197,94,0.25)'  :
              result.status === 'REVOKED' ? 'rgba(244,63,94,0.25)' :
              'rgba(245,158,11,0.25)'
            }`,
          }}>
            <CardContent>
              {/* Status header */}
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <StatusChip status={result.status} />
                  <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                    Certificate is <strong style={{ color: '#e2e8f0' }}>{result.status}</strong>
                  </Typography>
                </Box>
                <Button
                  id="copy-serial-btn"
                  size="small"
                  variant="outlined"
                  startIcon={<ContentCopyOutlined />}
                  onClick={() => navigator.clipboard.writeText(result.serialHex)}
                  sx={{ borderColor: 'rgba(255,255,255,0.1)', color: '#64748b',
                    '&:hover': { borderColor: '#6366f1', color: '#a5b4fc' } }}
                >
                  Copy serial
                </Button>
              </Box>

              <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)', mb: 2 }} />

              {/* Details */}
              <Row label="Serial Number" value={result.serialHex} mono />
              <Row label="Status"        value={result.status} />
              <Row label="Revoked at"    value={result.revocationTime
                ? new Date(result.revocationTime).toLocaleString() : null} />
              <Row label="Reason"        value={result.revocationReason} />

              {/* GOOD message */}
              {result.status === 'GOOD' && (
                <Alert severity="success" icon={<CheckCircleOutlined />} sx={{ mt: 2 }}>
                  This certificate is <strong>valid and in good standing</strong>. No action required.
                </Alert>
              )}

              {/* UNKNOWN message */}
              {result.status === 'UNKNOWN' && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  This serial number is <strong>not found</strong> in the OCSP database.
                  The certificate may have been issued by a different CA or may not yet be synchronised.
                </Alert>
              )}

              {/* REVOKED — renewal CTA */}
              {isRevoked && !renewResult && (
                <Alert
                  severity="error"
                  icon={<CancelOutlined />}
                  sx={{ mt: 2 }}
                  action={
                    <Button
                      id="request-renewal-btn"
                      color="inherit"
                      size="small"
                      variant="outlined"
                      startIcon={<AutorenewOutlined />}
                      onClick={() => setRenewOpen(true)}
                      sx={{ whiteSpace: 'nowrap', borderColor: 'rgba(244,63,94,0.5)',
                        '&:hover': { borderColor: '#f43f5e', background: 'rgba(244,63,94,0.1)' } }}
                    >
                      Request Renewal
                    </Button>
                  }
                >
                  This certificate has been <strong>revoked</strong>.
                  You can request KMS to issue a replacement signing certificate.
                </Alert>
              )}

              {/* Renewal success */}
              {renewResult && (
                <Alert severity="success" icon={<AutorenewOutlined />} sx={{ mt: 2 }}>
                  <Typography variant="body2" fontWeight={700} gutterBottom>
                    Renewal request accepted by KMS
                  </Typography>
                  <Row label="Request ID"   value={renewResult.requestId} mono />
                  <Row label="KMS Status"   value={renewResult.kmsStatus} />
                  <Row label="New valid until" value={renewResult.newNotAfter
                    ? new Date(renewResult.newNotAfter).toLocaleString() : null} />
                  <Row label="Submitted at" value={new Date(renewResult.submittedAt).toLocaleString()} />
                </Alert>
              )}
            </CardContent>
          </Card>
        )}
      </Collapse>

      {/* How-it-works callout */}
      {!result && !error && (
        <Card sx={{ background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.12)' }}>
          <CardContent>
            <Typography variant="subtitle2" fontWeight={700} sx={{ color: '#a5b4fc', mb: 1.5 }}>
              How it works
            </Typography>
            {[
              { step: '1', text: 'Enter the hex serial number of any certificate in the OCSP database.' },
              { step: '2', text: 'The admin API queries the revocation_status table and returns GOOD, REVOKED, or UNKNOWN.' },
              { step: '3', text: 'If the certificate is REVOKED you can request KMS to issue a new OCSP signing certificate via the "Request Renewal" button.' },
              { step: '4', text: 'The admin API calls POST /api/v1/kms/ocsp/signing-cert/renew on the KMS service, which rotates the signing key and issues a fresh certificate.' },
            ].map(({ step, text }) => (
              <Box key={step} sx={{ display: 'flex', gap: 1.5, mb: 1, '&:last-child': { mb: 0 } }}>
                <Box sx={{
                  width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '0.65rem', fontWeight: 700, color: '#fff',
                }}>
                  {step}
                </Box>
                <Typography variant="body2" sx={{ color: '#94a3b8', lineHeight: 1.5 }}>{text}</Typography>
              </Box>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Renewal dialog */}
      <Dialog
        open={renewOpen}
        onClose={() => setRenewOpen(false)}
        PaperProps={{ sx: { background: '#0d1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', minWidth: 480 } }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <AutorenewOutlined sx={{ color: '#6366f1' }} />
            <Typography variant="h6" fontWeight={700}>Request KMS Cert Renewal</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ color: '#94a3b8', mb: 2 }}>
            This will call the KMS service to rotate the OCSP signing certificate.
            The old revoked certificate will be replaced with a fresh 90-day cert.
          </DialogContentText>
          <TextField
            id="renewal-reason-input"
            fullWidth
            label="Renewal Reason"
            value={renewReason}
            onChange={(e) => setRenewReason(e.target.value)}
            multiline
            rows={2}
          />
          {renewError && <Alert severity="error" sx={{ mt: 2 }}>{renewError}</Alert>}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3 }}>
          <Button id="cancel-renewal-btn" onClick={() => setRenewOpen(false)} sx={{ color: '#64748b' }}>Cancel</Button>
          <Button
            id="confirm-renewal-btn"
            variant="contained"
            onClick={handleRenew}
            disabled={renewLoading}
            startIcon={renewLoading ? <CircularProgress size={16} color="inherit" /> : <AutorenewOutlined />}
            sx={{
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              '&:hover': { background: 'linear-gradient(135deg, #4f46e5, #7c3aed)' },
            }}
          >
            {renewLoading ? 'Requesting…' : 'Confirm Renewal'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}
