import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Title, Text, Card, Grid, Paper, TextInput, Textarea, Button, Badge, Alert, Collapse, Tabs, Switch, Radio, Group, Stack, Container, ThemeIcon, } from '@mantine/core';
import { IconSearch, IconShieldCheck, IconShieldX, IconHelp, IconCopy, IconKey, IconBolt, IconGauge, IconCpu, IconTerminal2, IconAlertCircle, IconCheck, IconShieldLock, IconLogin, IconArrowLeft, } from '@tabler/icons-react';
import { checkCertStatus, testOcspRequest, getReplicatedCertificates, getClientPresets, } from '../api/client';
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function StatusBadge({ status, }) {
    const map = {
        GOOD: {
            label: 'GOOD',
            color: 'teal',
            icon: <IconShieldCheck size={14}/>,
        },
        REVOKED: {
            label: 'REVOKED',
            color: 'red',
            icon: <IconShieldX size={14}/>,
        },
        UNKNOWN: {
            label: 'UNKNOWN',
            color: 'yellow',
            icon: <IconHelp size={14}/>,
        },
    };
    const entry = map[status] ?? {
        label: status,
        color: 'gray',
        icon: <IconHelp size={14}/>,
    };
    return (<Badge leftSection={entry.icon} color={entry.color} variant="filled" size="lg" radius="sm">
      {entry.label}
    </Badge>);
}
function DetailRow({ label, value, mono = false, }) {
    if (value === null || value === undefined || value === '')
        return null;
    return (<Group justify="space-between" align="flex-start" py={8} style={{
            borderBottom: '1px solid var(--mantine-color-dark-4)',
        }}>
      <Text fz="sm" c="dimmed" style={{ minWidth: 160 }}>
        {label}
      </Text>
      <Text fz={mono ? 'xs' : 'sm'} ff={mono ? "'JetBrains Mono', monospace" : 'inherit'} ta="right" style={{ wordBreak: 'break-all' }}>
        {value}
      </Text>
    </Group>);
}
// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export function CertCheckerPage({ publicMode = false }) {
    const navigate = useNavigate();
    const isAuthenticated = Boolean(localStorage.getItem('ocsp_bearer_token'));
    const [activeTab, setActiveTab] = useState('ocsp-tester');
    // Tab 0: Live OCSP Protocol Tester
    const [testSerial, setTestSerial] = useState('');
    const [issuerPem, setIssuerPem] = useState(() => localStorage.getItem('ocsp_checker_issuer_pem') || '');
    const [sampleGoodSerial, setSampleGoodSerial] = useState(null);
    const [sampleRevokedSerial, setSampleRevokedSerial] = useState(null);
    const [sampleHoldSerial, setSampleHoldSerial] = useState(null);
    useEffect(() => {
        const loadFromPublicPresets = () => {
            getClientPresets()
                .then((presets) => {
                const good = presets.find((p) => p.label?.includes('GOOD') && !p.label?.includes('HOLD'));
                const revoked = presets.find((p) => p.label?.includes('REVOKED'));
                const hold = presets.find((p) => p.label?.includes('HOLD'));
                if (good?.serialHex) {
                    setSampleGoodSerial(good.serialHex);
                    setTestSerial((prev) => prev || good.serialHex);
                    setSerial((prev) => prev || good.serialHex);
                }
                if (revoked?.serialHex)
                    setSampleRevokedSerial(revoked.serialHex);
                if (hold?.serialHex)
                    setSampleHoldSerial(hold.serialHex);
            })
                .catch(() => {});
        };

        if (publicMode || !isAuthenticated) {
            loadFromPublicPresets();
            return;
        }

        getReplicatedCertificates()
            .then((certs) => {
            const good = certs.find((c) => c.status === 'GOOD');
            const revoked = certs.find((c) => c.status === 'REVOKED' && c.revocationReason !== 'CERTIFICATE_HOLD');
            const hold = certs.find((c) => c.status === 'REVOKED' && c.revocationReason === 'CERTIFICATE_HOLD');
            if (good) {
                setSampleGoodSerial(good.serialNumberHex);
                setTestSerial((prev) => prev || good.serialNumberHex);
                setSerial((prev) => prev || good.serialNumberHex);
            }
            if (revoked)
                setSampleRevokedSerial(revoked.serialNumberHex);
            if (hold)
                setSampleHoldSerial(hold.serialNumberHex);
            if (!good && !revoked && !hold) {
                loadFromPublicPresets();
            }
        })
            .catch(() => {
            loadFromPublicPresets();
        });
    }, [publicMode, isAuthenticated]);
    const [includeNonce, setIncludeNonce] = useState(false);
    const [httpMethod, setHttpMethod] = useState('POST');
    const [testLoading, setTestLoading] = useState(false);
    const [testResult, setTestResult] = useState(null);
    const [testError, setTestError] = useState(null);
    const [copiedCmd, setCopiedCmd] = useState(false);
    // Tab 1: Database Status Lookup
    const [serial, setSerial] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    // Handle Live OCSP Test
    const handleRunOcspTest = async () => {
        const hex = testSerial.trim().replace(/[^0-9a-fA-F]/g, '');
        if (!hex)
            return;
        setTestLoading(true);
        setTestError(null);
        try {
            const res = await testOcspRequest(hex, includeNonce, httpMethod, issuerPem);
            if (res.error) {
                setTestError(res.error);
                setTestResult(null);
            }
            else {
                setTestResult(res);
            }
        }
        catch (err) {
            setTestError(err?.response?.data?.message ||
                err?.message ||
                'Failed to execute OCSP test');
            setTestResult(null);
        }
        finally {
            setTestLoading(false);
        }
    };
    // Handle Database Check
    const handleCheck = async () => {
        const hex = serial.trim().replace(/[^0-9a-fA-F]/g, '');
        if (!hex)
            return;
        setLoading(true);
        setResult(null);
        setError(null);
        try {
            const data = await checkCertStatus(hex);
            setResult(data);
        }
        catch (e) {
            const msg = e.response?.status === 400
                ? 'Invalid serial number format.'
                : 'Failed to contact the admin API. Is the service running?';
            setError(msg);
        }
        finally {
            setLoading(false);
        }
    };
    const isRevoked = result?.status === 'REVOKED';
    const content = (<Box className="page-enter">
      {/* Header */}
      <Group justify="space-between" align="flex-start" mb="lg" wrap="wrap">
        <Box>
          <Group gap="sm">
            {publicMode && (
              <ThemeIcon size={36} radius="md" variant="gradient" gradient={{ from: 'teal.6', to: 'indigo.6' }}>
                <IconShieldLock size={20} />
              </ThemeIcon>
            )}
            <Box>
              <Group gap="xs">
                <Title order={3} fw={700} c="white">
                  {publicMode ? 'Incert Public OCSP Client & RFC 6960 Validator' : 'Certificate & OCSP Testing'}
                </Title>
                {publicMode && (
                  <Badge color="teal" variant="light" size="sm">
                    PUBLIC ACCESS
                  </Badge>
                )}
              </Group>
              <Text fz="sm" c="dimmed" mt={4}>
                Test real RFC 6960 OCSP requests (Nonce vs Nonce-Free) to inspect
                dynamic PKCS#11 signing and signature verification against the responder.
              </Text>
            </Box>
          </Group>
        </Box>

        {publicMode && (
          <Group gap="xs">
            {isAuthenticated ? (
              <Button
                variant="light"
                color="indigo"
                size="sm"
                leftSection={<IconArrowLeft size={16} />}
                onClick={() => navigate('/dashboard')}
              >
                Back to Admin Console
              </Button>
            ) : (
              <Button
                variant="gradient"
                gradient={{ from: 'indigo.6', to: 'violet.6' }}
                size="sm"
                leftSection={<IconLogin size={16} />}
                onClick={() => navigate('/login')}
              >
                Sign In to Admin Console
              </Button>
            )}
          </Group>
        )}
      </Group>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={setActiveTab} mb="lg" color="indigo">
        <Tabs.List>
          <Tabs.Tab value="ocsp-tester" leftSection={<IconBolt size={16}/>}>
            Live OCSP Request Tester (RFC 6960)
          </Tabs.Tab>
          {!publicMode && (
            <Tabs.Tab value="db-lookup" leftSection={<IconSearch size={16}/>}>
              Database Status Lookup
            </Tabs.Tab>
          )}
        </Tabs.List>

        {/* =================================================================== */}
        {/* TAB 0: LIVE OCSP REQUEST TESTER                                    */}
        {/* =================================================================== */}
        <Tabs.Panel value="ocsp-tester" pt="md">
          <Card p="lg" radius="md" mb="lg" style={{
            backgroundColor: 'var(--mantine-color-dark-6)',
            border: '1px solid var(--mantine-color-dark-4)',
        }}>
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
              {sampleGoodSerial && (<Badge color="teal" variant="light" style={{ cursor: 'pointer' }} onClick={() => setTestSerial(sampleGoodSerial)}>
                  Sample GOOD ({sampleGoodSerial.slice(0, 8)}…)
                </Badge>)}
              {sampleRevokedSerial && (<Badge color="red" variant="light" style={{ cursor: 'pointer' }} onClick={() => setTestSerial(sampleRevokedSerial)}>
                  Sample REVOKED ({sampleRevokedSerial.slice(0, 8)}…)
                </Badge>)}
              {sampleHoldSerial && (<Badge color="yellow" variant="light" style={{ cursor: 'pointer' }} onClick={() => setTestSerial(sampleHoldSerial)}>
                  Sample HOLD ({sampleHoldSerial.slice(0, 8)}…)
                </Badge>)}
            </Group>

            <Grid gutter="md">
              <Grid.Col span={{ base: 12, md: 7 }}>
                <TextInput label="Certificate Serial Number (hex)" description="Target end-entity certificate serial" value={testSerial} onChange={(e) => setTestSerial(e.target.value)} leftSection={<IconKey size={16} color="#818cf8"/>} styles={{
            input: {
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.85rem',
            },
        }}/>
              </Grid.Col>

              <Grid.Col span={{ base: 12, md: 5 }}>
                <Text fz="xs" fw={500} c="dimmed" mb={6}>
                  Transport Protocol
                </Text>
                <Radio.Group value={httpMethod} onChange={(val) => setHttpMethod(val)}>
                  <Group mt="xs">
                    <Radio value="POST" label="POST (DER binary)"/>
                    <Radio value="GET" label="GET (base64url)"/>
                  </Group>
                </Radio.Group>
              </Grid.Col>

              <Grid.Col span={12}>
                <Textarea label="Issuer CA Certificate (PEM)" description="Required to build CertID and verify the OCSP response signature (download from KMS > Certificate Authorities)" placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'} value={issuerPem} onChange={(e) => {
            const val = e.currentTarget.value;
            setIssuerPem(val);
            localStorage.setItem('ocsp_checker_issuer_pem', val);
        }} autosize minRows={3} maxRows={6} styles={{
            input: {
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.75rem',
            },
        }}/>
              </Grid.Col>

              <Grid.Col span={12}>
                <Paper p="md" radius="sm" style={{
            backgroundColor: 'var(--mantine-color-dark-5)',
            border: '1px solid var(--mantine-color-dark-4)',
        }}>
                  <Switch checked={includeNonce} onChange={(e) => setIncludeNonce(e.currentTarget.checked)} label="Include Nonce Extension (RFC 6960 §4.4.1)" color="indigo"/>
                  <Text fz="xs" c={includeNonce ? 'yellow.5' : 'teal.4'} mt={6}>
                    {includeNonce
            ? '⚠️ NONCE INCLUDED: Injects an 8-byte unique random nonce. Responder echoes it back in the signature.'
            : '⚡ NONCE-FREE: Standard RFC 6960 query without nonce.'}
                  </Text>
                </Paper>
              </Grid.Col>
            </Grid>

            <Group justify="flex-end" mt="lg">
              <Button size="md" onClick={handleRunOcspTest} disabled={testLoading || !testSerial.trim()} loading={testLoading} leftSection={<IconBolt size={18}/>} style={{
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
        }}>
                Send OCSP Request
              </Button>
            </Group>
          </Card>

          {testError && (<Alert icon={<IconAlertCircle size={16}/>} color="red" title="Request Error" mb="lg">
              {testError}
            </Alert>)}

          {/* Test results */}
          {testResult && (<Card p="lg" radius="md" mb="lg" style={{
                backgroundColor: 'var(--mantine-color-dark-6)',
                border: '1px solid rgba(99,102,241,0.4)',
            }}>
              <Group justify="space-between" align="center" mb="md">
                <Group gap="sm">
                  <StatusBadge status={testResult.certStatus}/>
                  <Title order={4} fw={700}>
                    OCSP Response Received
                  </Title>
                </Group>

                <Badge leftSection={<IconGauge size={14}/>} color={testResult.latencyMs < 10 ? 'teal' : 'indigo'} variant="filled" size="lg">
                  {testResult.latencyMs} ms
                </Badge>
              </Group>

              {testResult.certStatus === 'UNKNOWN' && (
                <Alert icon={<IconHelp size={18}/>} color="yellow" title="Why Status is UNKNOWN" mb="md">
                  {testResult.unknownReason || 'No certificate in OCSP database matched the RFC 6960 CertID (issuerNameHash + issuerKeyHash + serialNumber).'}
                </Alert>
              )}

              {/* KPI Banner */}
              <Grid gutter="md" mb="md">
                <Grid.Col span={{ base: 12, sm: 4 }}>
                  <Paper p="sm" radius="sm" style={{
                backgroundColor: 'rgba(34,197,94,0.08)',
                border: '1px solid rgba(34,197,94,0.3)',
            }}>
                    <Text fz="xs" c="dimmed">
                      Signing Architecture
                    </Text>
                    <Group gap="xs" mt={4}>
                      <IconCpu size={18} color="#22c55e"/>
                      <Text fz="sm" fw={700} c="teal.4">
                        ⚡ DIRECT SIGNING (NO CACHE)
                      </Text>
                    </Group>
                  </Paper>
                </Grid.Col>

                <Grid.Col span={{ base: 12, sm: 4 }}>
                  <Paper p="sm" radius="sm" style={{
                backgroundColor: 'var(--mantine-color-dark-5)',
                border: '1px solid var(--mantine-color-dark-4)',
            }}>
                    <Text fz="xs" c="dimmed">
                      Nonce Status
                    </Text>
                    <Text fz="sm" fw={700} mt={4} c={testResult.includeNonce
                ? testResult.nonceMatched
                    ? 'teal.4'
                    : 'red.4'
                : 'dimmed'}>
                      {testResult.includeNonce
                ? testResult.nonceMatched
                    ? '✅ Nonce Echoed & Matched'
                    : '❌ Nonce Mismatch'
                : 'None (Nonce-Free Request)'}
                    </Text>
                  </Paper>
                </Grid.Col>

                <Grid.Col span={{ base: 12, sm: 4 }}>
                  <Paper p="sm" radius="sm" style={{
                backgroundColor: 'var(--mantine-color-dark-5)',
                border: '1px solid var(--mantine-color-dark-4)',
            }}>
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
                <DetailRow label="Target Serial" value={testResult.serialHex} mono/>
                <DetailRow label="Certificate Status" value={testResult.certStatus}/>
                {testResult.unknownReason && (<DetailRow label="Unknown Reason" value={testResult.unknownReason}/>)}
                {testResult.issuerNameHashHex && (<DetailRow label="Issuer Name Hash (SHA-1)" value={testResult.issuerNameHashHex} mono/>)}
                {testResult.issuerKeyHashHex && (<DetailRow label="Issuer Key Hash (SHA-1)" value={testResult.issuerKeyHashHex} mono/>)}
                {testResult.revocationTime && (<DetailRow label="Revocation Time" value={testResult.revocationTime}/>)}
                {testResult.revocationReason && (<DetailRow label="Revocation Reason" value={testResult.revocationReason}/>)}
                <DetailRow label="This Update" value={testResult.thisUpdate}/>
                <DetailRow label="Next Update" value={testResult.nextUpdate}/>
                {testResult.producedAt && (<DetailRow label="Produced At" value={testResult.producedAt}/>)}
                {testResult.signerSubject && (<DetailRow label="Signer Subject" value={testResult.signerSubject} mono/>)}
                {testResult.responderId && (<DetailRow label="Responder ID" value={testResult.responderId} mono/>)}
                {testResult.nonceSent && (<DetailRow label="Nonce Sent" value={`0x${testResult.nonceSent}`} mono/>)}
                {testResult.nonceEchoed && (<DetailRow label="Nonce Echoed" value={`0x${testResult.nonceEchoed}`} mono/>)}
                <DetailRow label="Signing Mode" value={testResult.cacheVerdict}/>
              </Stack>

              {/* RFC 6960 Step-by-Step Verification Checklist */}
              {Array.isArray(testResult.checks) && testResult.checks.length > 0 && (
                <Box mb="md">
                  <Text fz="xs" fw={700} c="indigo.3" mb={6} tt="uppercase">
                    RFC 6960 / RFC 8954 Cryptographic Verification Checks
                  </Text>
                  <Stack gap={6}>
                    {testResult.checks.map((chk, idx) => {
                      const color = chk.outcome === 'PASS' ? 'teal' : (chk.outcome === 'FAIL' ? 'red' : 'yellow');
                      return (
                        <Paper
                          key={`${chk.name}-${idx}`}
                          px="sm"
                          py={6}
                          radius="sm"
                          style={{
                            backgroundColor: 'var(--mantine-color-dark-5)',
                            border: '1px solid var(--mantine-color-dark-4)',
                          }}
                        >
                          <Group justify="space-between" wrap="nowrap" align="flex-start">
                            <Group gap="xs" wrap="nowrap">
                              <Badge size="xs" color={color} variant="filled">
                                {chk.outcome}
                              </Badge>
                              <Text fz="xs" fw={600} c="white">
                                {chk.name}
                              </Text>
                            </Group>
                            <Text fz="xs" c="dimmed" ta="right" style={{ wordBreak: 'break-word' }}>
                              {chk.detail}
                            </Text>
                          </Group>
                        </Paper>
                      );
                    })}
                  </Stack>
                </Box>
              )}

              {/* Terminal command */}
              <Box mt="md">
                <Group justify="space-between" mb={6}>
                  <Group gap={6}>
                    <IconTerminal2 size={16} color="#818cf8"/>
                    <Text fz="xs" fw={700} c="indigo.3">
                      TERMINAL / OPENSSL EQUIVALENT
                    </Text>
                  </Group>

                  <Button size="compact-xs" variant="subtle" color={copiedCmd ? 'teal' : 'indigo'} leftSection={copiedCmd ? (<IconCheck size={14}/>) : (<IconCopy size={14}/>)} onClick={() => {
                navigator.clipboard.writeText(testResult.opensslCommand ?? '');
                setCopiedCmd(true);
                setTimeout(() => setCopiedCmd(false), 2000);
            }}>
                    {copiedCmd ? 'Copied Command!' : 'Copy OpenSSL Command'}
                  </Button>
                </Group>

                <Paper p="sm" radius="sm" style={{
                backgroundColor: '#080c14',
                border: '1px solid var(--mantine-color-dark-4)',
            }}>
                  <Text fz="xs" ff="'JetBrains Mono', monospace" c="indigo.2" style={{
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
            }}>
                    {testResult.opensslCommand}
                  </Text>
                </Paper>
              </Box>
            </Card>)}
        </Tabs.Panel>

        {/* =================================================================== */}
        {/* TAB 1: DATABASE STATUS LOOKUP & RENEWAL                            */}
        {/* =================================================================== */}
        <Tabs.Panel value="db-lookup" pt="md">
          <Card p="lg" radius="md" mb="lg" style={{
            backgroundColor: 'var(--mantine-color-dark-6)',
            border: '1px solid var(--mantine-color-dark-4)',
        }}>
            <Group align="flex-start" gap="md">
              <Box style={{ flex: 1 }}>
                <TextInput id="serial-input" label="Certificate Serial Number (hex)" placeholder="e.g. 00b59d41baf78afe0de1bbe7ae28c0450f" value={serial} onChange={(e) => setSerial(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleCheck()} leftSection={<IconKey size={16} color="#6366f1"/>} description="Enter the hex-encoded serial number of the certificate to check" styles={{
            input: {
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.85rem',
            },
        }}/>
              </Box>
              <Button id="check-cert-btn" onClick={handleCheck} disabled={loading || !serial.trim()} loading={loading} leftSection={<IconSearch size={16}/>} mt={24} style={{
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            minWidth: 140,
        }}>
                Check Status
              </Button>
            </Group>
          </Card>

          {error && (<Alert icon={<IconAlertCircle size={16}/>} color="red" title="Lookup Error" mb="lg">
              {error}
            </Alert>)}

          <Collapse in={!!result}>
            {result && (<Card p="lg" radius="md" mb="lg" style={{
                backgroundColor: 'var(--mantine-color-dark-6)',
                border: `1px solid ${result.status === 'GOOD'
                    ? 'rgba(34,197,94,0.3)'
                    : result.status === 'REVOKED'
                        ? 'rgba(244,63,94,0.3)'
                        : 'rgba(245,158,11,0.3)'}`,
            }}>
                <Group justify="space-between" align="center" mb="md">
                  <Group gap="sm">
                    <StatusBadge status={result.status}/>
                    <Text fz="sm" c="dimmed">
                      Certificate is{' '}
                      <strong style={{ color: 'var(--mantine-color-dark-0)' }}>
                        {result.status}
                      </strong>
                    </Text>
                  </Group>

                  <Button id="copy-serial-btn" size="xs" variant="default" leftSection={<IconCopy size={14}/>} onClick={() => navigator.clipboard.writeText(result.serialHex)}>
                    Copy Serial
                  </Button>
                </Group>

                <Stack gap={0} mb="md">
                  <DetailRow label="Serial Number" value={result.serialHex} mono/>
                  <DetailRow label="Status" value={result.status}/>
                  {result.issuerNameHashHex && (<DetailRow label="Stored Issuer Name Hash" value={result.issuerNameHashHex} mono/>)}
                  {result.issuerKeyHashHex && (<DetailRow label="Stored Issuer Key Hash" value={result.issuerKeyHashHex} mono/>)}
                  <DetailRow label="Revoked at" value={result.revocationTime
                ? new Date(result.revocationTime).toLocaleString()
                : null}/>
                  <DetailRow label="Reason" value={result.revocationReason}/>
                </Stack>

                {result.status === 'GOOD' && (<Alert icon={<IconShieldCheck size={18}/>} color="teal" title="Good Standing">
                    This certificate is{' '}
                    <strong>valid and in good standing</strong>. No action
                    required.
                  </Alert>)}

                {result.status === 'UNKNOWN' && (<Alert icon={<IconHelp size={18}/>} color="yellow" title="Why Status is UNKNOWN">
                    {result.unknownReason || (
                      <>
                        This serial number is <strong>not found</strong> in the OCSP
                        database. The certificate may have been issued by a different
                        CA or may not yet be synchronised.
                      </>
                    )}
                  </Alert>)}

                {isRevoked && (<Alert icon={<IconShieldX size={18}/>} color="red" title="Certificate Revoked">
                    <Text fz="sm">
                      This certificate has been <strong>revoked</strong> via RabbitMQ event stream from KMS.
                    </Text>
                  </Alert>)}
              </Card>)}
          </Collapse>
        </Tabs.Panel>
      </Tabs>
    </Box>);

    if (publicMode) {
        return (
            <Box
                style={{
                    minHeight: '100vh',
                    backgroundColor: 'var(--mantine-color-dark-8)',
                    backgroundImage: 'radial-gradient(circle at 50% 10%, rgba(99, 102, 241, 0.1) 0%, transparent 55%)',
                    color: 'var(--mantine-color-dark-0)',
                    padding: '32px 16px',
                }}
            >
                <Container size="lg">
                    {content}
                </Container>
            </Box>
        );
    }

    return content;
}
