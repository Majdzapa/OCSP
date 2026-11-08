import { useState } from 'react'
import {
  Box,
  Typography,
  Card,
  CardContent,
  TextField,
  InputAdornment,
  Button,
  CircularProgress,
  Chip,
  Alert,
  Divider,
  Collapse,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Tabs,
  Tab,
  FormControlLabel,
  Switch,
  RadioGroup,
  Radio,
  Grid,
  Paper,
} from '@mui/material'
import {
  SearchOutlined,
  CheckCircleOutlined,
  CancelOutlined,
  HelpOutlineOutlined,
  AutorenewOutlined,
  ContentCopyOutlined,
  KeyOutlined,
  BoltOutlined,
  SpeedOutlined,
  StorageOutlined,
  TerminalOutlined,
} from '@mui/icons-material'
import { checkCertStatus, requestCertRenewal, testOcspRequest } from '../api/client'
import type { CertStatusResponse, RenewRequestResponse, OcspTestResult } from '../types/api'

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
  if (value === null || value === undefined || value === '') return null
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
  const [tabIndex, setTabIndex] = useState<number>(0)

  // Tab 0: Live OCSP Protocol Tester
  const [testSerial, setTestSerial] = useState('00b59d41baf78afe0de1bbe7ae28c0450f') // ee-01
  const [includeNonce, setIncludeNonce] = useState(false) // Nonce-free by default for L2 cache testing!
  const [httpMethod, setHttpMethod] = useState<'POST' | 'GET'>('POST')
  const [testLoading, setTestLoading] = useState(false)
  const [testResult, setTestResult] = useState<OcspTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [copiedCmd, setCopiedCmd] = useState(false)

  // Tab 1: Database Status Lookup
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
      setTestError(err?.response?.data?.message || err?.message || 'Failed to execute OCSP test')
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
        <Typography variant="h5" fontWeight={700}>Certificate & OCSP Testing</Typography>
        <Typography variant="body2" sx={{ color: '#64748b', mt: 0.5 }}>
          Test real RFC 6960 OCSP requests (Nonce vs Nonce-Free) to inspect L1/L2 cache hits and SoftHSM2 signing, or check DB status.
        </Typography>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'rgba(255,255,255,0.08)', mb: 3 }}>
        <Tabs
          value={tabIndex}
          onChange={(_, val) => setTabIndex(val)}
          sx={{
            '& .MuiTab-root': { textTransform: 'none', fontWeight: 600, fontSize: '0.9rem' },
            '& .Mui-selected': { color: '#818cf8' },
            '& .MuiTabs-indicator': { backgroundColor: '#818cf8' },
          }}
        >
          <Tab icon={<BoltOutlined sx={{ fontSize: 18 }} />} iconPosition="start" label="Live OCSP Request Tester (RFC 6960)" />
          <Tab icon={<SearchOutlined sx={{ fontSize: 18 }} />} iconPosition="start" label="Database Status Lookup" />
        </Tabs>
      </Box>

      {/* =================================================================== */}
      {/* TAB 0: LIVE OCSP REQUEST TESTER                                    */}
      {/* =================================================================== */}
      {tabIndex === 0 && (
        <Box>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="subtitle1" fontWeight={700} sx={{ color: '#e2e8f0', mb: 1 }}>
                Configure OCSP Request
              </Typography>
              <Typography variant="body2" sx={{ color: '#94a3b8', mb: 2 }}>
                Constructs a standard DER-encoded RFC 6960 OCSP request and measures the response latency, L2 cache hit, and nonce echoing.
              </Typography>

              {/* Quick sample buttons */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2.5, flexWrap: 'wrap' }}>
                <Typography variant="caption" sx={{ color: '#64748b' }}>Quick Presets:</Typography>
                <Chip
                  label="ee-01 (GOOD)"
                  size="small"
                  onClick={() => setTestSerial('00b59d41baf78afe0de1bbe7ae28c0450f')}
                  sx={{ cursor: 'pointer', bgcolor: 'rgba(34,197,94,0.12)', color: '#22c55e' }}
                />
                <Chip
                  label="ee-02 (REVOKED)"
                  size="small"
                  onClick={() => setTestSerial('008a5232e619344f2ebdb9b35f93e6a70d')}
                  sx={{ cursor: 'pointer', bgcolor: 'rgba(244,63,94,0.12)', color: '#f43f5e' }}
                />
                <Chip
                  label="ee-03 (HOLD / GOOD)"
                  size="small"
                  onClick={() => setTestSerial('00dcd6e3751e8e68a43f3fc6561007e833')}
                  sx={{ cursor: 'pointer', bgcolor: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}
                />
              </Box>

              <Grid container spacing={2.5}>
                {/* Serial input */}
                <Grid item xs={12} md={7}>
                  <TextField
                    fullWidth
                    label="Certificate Serial Number (hex)"
                    value={testSerial}
                    onChange={(e) => setTestSerial(e.target.value)}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <KeyOutlined sx={{ color: '#818cf8' }} />
                        </InputAdornment>
                      ),
                      sx: { fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem' },
                    }}
                    helperText="Target end-entity certificate serial"
                  />
                </Grid>

                {/* Method selector */}
                <Grid item xs={12} md={5}>
                  <Typography variant="caption" sx={{ color: '#94a3b8', display: 'block', mb: 0.5 }}>
                    Transport Protocol
                  </Typography>
                  <RadioGroup
                    row
                    value={httpMethod}
                    onChange={(e) => setHttpMethod(e.target.value as any)}
                  >
                    <FormControlLabel
                      value="POST"
                      control={<Radio size="small" sx={{ color: '#818cf8', '&.Mui-checked': { color: '#818cf8' } }} />}
                      label={<Typography variant="body2">POST (DER binary)</Typography>}
                    />
                    <FormControlLabel
                      value="GET"
                      control={<Radio size="small" sx={{ color: '#818cf8', '&.Mui-checked': { color: '#818cf8' } }} />}
                      label={<Typography variant="body2">GET (base64url)</Typography>}
                    />
                  </RadioGroup>
                </Grid>

                {/* Nonce toggle */}
                <Grid item xs={12}>
                  <Paper sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={includeNonce}
                          onChange={(e) => setIncludeNonce(e.target.checked)}
                          color="primary"
                        />
                      }
                      label={
                        <Typography variant="body2" fontWeight={600}>
                          Include Nonce Extension (RFC 6960 §4.4.1)
                        </Typography>
                      }
                    />

                    <Typography variant="caption" sx={{ display: 'block', mt: 0.5, color: includeNonce ? '#f59e0b' : '#22c55e' }}>
                      {includeNonce
                        ? '⚠️ NONCE INCLUDED: Injects an 8-byte unique random nonce. Responder echoes it back in the signature. L2 Response Cache is BYPASSED because nonces are single-use.'
                        : '⚡ NONCE-FREE (DEFAULT FOR BROWSERS & STAPLING): Requests without nonces are stored into the L2 Pre-Signed Response Cache. Running this a second time will trigger an instant L2 Cache HIT!'}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
                <Button
                  variant="contained"
                  size="large"
                  onClick={handleRunOcspTest}
                  disabled={testLoading || !testSerial.trim()}
                  startIcon={testLoading ? <CircularProgress size={16} color="inherit" /> : <BoltOutlined />}
                  sx={{
                    px: 4,
                    py: 1.2,
                    fontWeight: 700,
                    background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                    boxShadow: '0 4px 14px rgba(99,102,241,0.4)',
                  }}
                >
                  {testLoading ? 'Processing Request…' : 'Send OCSP Request'}
                </Button>
              </Box>
            </CardContent>
          </Card>

          {testError && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {testError}
            </Alert>
          )}

          {/* Test results */}
          {testResult && (
            <Card sx={{ mb: 3, border: '1px solid rgba(99,102,241,0.3)' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <StatusChip status={testResult.certStatus as any} />
                    <Typography variant="h6" fontWeight={700}>
                      OCSP Response Received
                    </Typography>
                  </Box>

                  <Chip
                    icon={<SpeedOutlined sx={{ fontSize: 16 }} />}
                    label={`${testResult.latencyMs} ms`}
                    color={testResult.latencyMs < 5 ? 'success' : 'primary'}
                    sx={{ fontWeight: 700 }}
                  />
                </Box>

                {/* Result KPI banner */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={12} sm={4}>
                    <Paper sx={{ p: 2, bgcolor: testResult.l2Hit ? 'rgba(34,197,94,0.08)' : 'rgba(255,255,255,0.02)', border: `1px solid ${testResult.l2Hit ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.06)'}` }}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>L2 Cache Status</Typography>
                      <Box sx={{ mt: 0.5, display: 'flex', alignItems: 'center', gap: 1 }}>
                        <StorageOutlined sx={{ color: testResult.l2Hit ? '#22c55e' : '#818cf8', fontSize: 20 }} />
                        <Typography variant="body2" fontWeight={700} sx={{ color: testResult.l2Hit ? '#22c55e' : '#e2e8f0' }}>
                          {testResult.l2Hit ? '⚡ L2 CACHE HIT' : testResult.includeNonce ? '🚫 BYPASSED (Nonce)' : '📥 L2 MISS (Saved to L2)'}
                        </Typography>
                      </Box>
                    </Paper>
                  </Grid>

                  <Grid item xs={12} sm={4}>
                    <Paper sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Nonce Status</Typography>
                      <Typography variant="body2" fontWeight={700} sx={{ mt: 0.5, color: testResult.includeNonce ? (testResult.nonceMatched ? '#22c55e' : '#f43f5e') : '#94a3b8' }}>
                        {testResult.includeNonce
                          ? (testResult.nonceMatched ? '✅ Nonce Echoed & Matched' : '❌ Nonce Mismatch')
                          : 'None (Nonce-Free Request)'}
                      </Typography>
                    </Paper>
                  </Grid>

                  <Grid item xs={12} sm={4}>
                    <Paper sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>Response Size</Typography>
                      <Typography variant="body2" fontWeight={700} sx={{ mt: 0.5, color: '#e2e8f0' }}>
                        {testResult.responseSizeBytes} bytes (DER)
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>

                {/* Details rows */}
                <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)', mb: 2 }} />
                <Row label="Target Serial" value={testResult.serialHex} mono />
                <Row label="Certificate Status" value={testResult.certStatus} />
                {testResult.revocationTime && (
                  <Row label="Revocation Time" value={testResult.revocationTime} />
                )}
                {testResult.revocationReason && (
                  <Row label="Revocation Reason" value={testResult.revocationReason} />
                )}
                <Row label="This Update" value={testResult.thisUpdate} />
                <Row label="Next Update" value={testResult.nextUpdate} />
                {testResult.nonceSent && (
                  <Row label="Nonce Sent" value={`0x${testResult.nonceSent}`} mono />
                )}
                {testResult.nonceEchoed && (
                  <Row label="Nonce Echoed" value={`0x${testResult.nonceEchoed}`} mono />
                )}
                {testResult.cacheKey && (
                  <Row label="L2 Cache Key" value={testResult.cacheKey} mono />
                )}
                <Row label="Cache Explanation" value={testResult.cacheVerdict} />

                {/* Terminal commands box */}
                <Box sx={{ mt: 3 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="caption" sx={{ color: '#818cf8', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <TerminalOutlined sx={{ fontSize: 14 }} />
                      TERMINAL / OPENSSL EQUIVALENT
                    </Typography>

                    <Button
                      size="small"
                      startIcon={<ContentCopyOutlined />}
                      onClick={() => {
                        navigator.clipboard.writeText(testResult.opensslCommand)
                        setCopiedCmd(true)
                        setTimeout(() => setCopiedCmd(false), 2000)
                      }}
                      sx={{ textTransform: 'none', fontSize: '0.75rem', color: copiedCmd ? '#22c55e' : '#818cf8' }}
                    >
                      {copiedCmd ? 'Copied Command!' : 'Copy OpenSSL Command'}
                    </Button>
                  </Box>

                  <Paper sx={{ p: 1.5, bgcolor: '#080c14', border: '1px solid rgba(255,255,255,0.08)' }}>
                    <Typography
                      variant="caption"
                      component="pre"
                      sx={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.75rem',
                        color: '#a5b4fc',
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {testResult.opensslCommand}
                    </Typography>
                  </Paper>
                </Box>
              </CardContent>
            </Card>
          )}
        </Box>
      )}

      {/* =================================================================== */}
      {/* TAB 1: DATABASE STATUS LOOKUP & RENEWAL                            */}
      {/* =================================================================== */}
      {tabIndex === 1 && (
        <Box>
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
        </Box>
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
