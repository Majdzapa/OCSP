import { Box, Typography, Card, CardContent, Grid, Chip, LinearProgress, Alert } from '@mui/material'
import { VerifiedUserOutlined, WarningAmberOutlined, AutorenewOutlined } from '@mui/icons-material'
import { useDashboardStats } from '../hooks/useDashboardStats'

export function SigningCertPage() {
  const { stats, loading } = useDashboardStats(30_000)

  const days = stats?.ocspSigningCertDaysRemaining ?? null
  const isWarning  = days !== null && days <= 14
  const isCritical = days !== null && days <= 7

  return (
    <Box className="page-enter">
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>OCSP Signing Certificate</Typography>
        <Typography variant="body2" sx={{ color: '#64748b', mt: 0.5 }}>
          Delegated signing certificate lifecycle — issued by Incert, HSM-backed
        </Typography>
      </Box>

      {isCritical && (
        <Alert severity="error" icon={<WarningAmberOutlined />} sx={{ mb: 3 }}>
          <strong>CRITICAL:</strong> The OCSP signing certificate expires in {days} day{days !== 1 ? 's' : ''}.
          Immediate rotation required to avoid responder outage.
        </Alert>
      )}
      {isWarning && !isCritical && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          The OCSP signing certificate expires in {days} days. Plan rotation now.
        </Alert>
      )}

      <Grid container spacing={2}>
        {/* Validity panel */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <VerifiedUserOutlined sx={{ color: isCritical ? '#f43f5e' : '#22c55e', fontSize: 28 }} />
                <Box>
                  <Typography variant="h6">Active Signing Cert</Typography>
                  <Chip
                    label={isCritical ? 'CRITICAL' : isWarning ? 'EXPIRING SOON' : 'Valid'}
                    color={isCritical ? 'error' : isWarning ? 'warning' : 'success'}
                    size="small"
                  />
                </Box>
              </Box>

              {loading ? (
                <LinearProgress />
              ) : (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2" sx={{ color: '#64748b' }}>Days remaining</Typography>
                    <Typography variant="body2" fontWeight={700}
                      sx={{ color: isCritical ? '#f43f5e' : isWarning ? '#f59e0b' : '#22c55e' }}>
                      {days} days
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={Math.min(100, ((days ?? 0) / 90) * 100)}
                    color={isCritical ? 'error' : isWarning ? 'warning' : 'success'}
                    sx={{ mb: 2 }}
                  />

                  {/* Static metadata (loaded from KMS at startup in real impl) */}
                  {[
                    { label: 'Key Algorithm',   value: 'RSA-4096' },
                    { label: 'Signature Alg',   value: 'SHA256withRSA' },
                    { label: 'EKU',             value: 'id-kp-OCSPSigning' },
                    { label: 'nocheck ext',     value: 'id-pkix-ocsp-nocheck ✓' },
                    { label: 'KMS Key Ref',     value: 'ocsp-signing-key-01' },
                    { label: 'Issued by',       value: 'Incert-Root-CA-01' },
                  ].map(({ label, value }) => (
                    <Box key={label} sx={{ display: 'flex', justifyContent: 'space-between', py: 0.75,
                      borderBottom: '1px solid rgba(255,255,255,0.05)', '&:last-child': { borderBottom: 'none' } }}>
                      <Typography variant="body2" sx={{ color: '#64748b' }}>{label}</Typography>
                      <Typography variant="caption" sx={{ fontFamily: 'JetBrains Mono, monospace', color: '#a5b4fc' }}>
                        {value}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Auto-rotation info */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <AutorenewOutlined sx={{ color: '#6366f1', fontSize: 28 }} />
                <Typography variant="h6">Auto-Rotation Policy</Typography>
              </Box>
              {[
                { label: 'Rotation trigger',    value: 'T-14 days before expiry' },
                { label: 'Rotation method',     value: 'KMS auto-issues new cert' },
                { label: 'Cert lifetime',       value: '90 days' },
                { label: 'Alert at T-14 days',  value: 'Prometheus alert → PagerDuty' },
                { label: 'Alert at T-7 days',   value: 'Critical — page on-call' },
                { label: 'Alert at T-1 day',    value: 'Critical — escalation' },
                { label: 'Private key',         value: 'Stays in KMS/HSM — never exported' },
              ].map(({ label, value }) => (
                <Box key={label} sx={{ display: 'flex', justifyContent: 'space-between', py: 0.75,
                  borderBottom: '1px solid rgba(255,255,255,0.05)', '&:last-child': { borderBottom: 'none' } }}>
                  <Typography variant="body2" sx={{ color: '#64748b' }}>{label}</Typography>
                  <Typography variant="body2" sx={{ color: '#e2e8f0', textAlign: 'right', maxWidth: '55%' }}>
                    {value}
                  </Typography>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  )
}
