import React, { useState, useEffect, useCallback } from 'react';
import { Box, Title, Text, Card, Grid, Table, Badge, Button, Group, Stack, Alert, Modal, Switch, TextInput, Textarea, Paper, Code, CopyButton, ActionIcon, Tooltip, Divider, } from '@mantine/core';
import { IconAlertTriangle, IconShieldCheck, IconRefresh, IconCertificate, IconCopy, IconCheck, IconDownload, IconKey, IconClock, } from '@tabler/icons-react';
import { getSigningCertValidityReport, runSigningCertValidityCheckNow, createSigningCertRenewalRequest, addSigningCertificate, } from '../api/client';
function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
export const SigningCertValidityPage = () => {
    const [report, setReport] = useState(null);
    const [loading, setLoading] = useState(true);
    const [checkLoading, setCheckLoading] = useState(false);
    const [banner, setBanner] = useState(null);
    // Renewal Request Modal State
    const [renewModalOpen, setRenewModalOpen] = useState(false);
    const [targetCert, setTargetCert] = useState(null);
    const [reuseExistingKey, setReuseExistingKey] = useState(true);
    const [newKeyLabel, setNewKeyLabel] = useState('');
    const [csrLoading, setCsrLoading] = useState(false);
    const [csrResult, setCsrResult] = useState(null);
    // Optional Direct Import of Renewed Certificate inside Modal
    const [renewedAlias, setRenewedAlias] = useState('');
    const [renewedPem, setRenewedPem] = useState('');
    const [activateRenewed, setActivateRenewed] = useState(true);
    const [importLoading, setImportLoading] = useState(false);
    const loadReport = useCallback(async () => {
        setLoading(true);
        try {
            const data = await getSigningCertValidityReport();
            setReport(data);
        }
        catch (err) {
            setBanner({
                color: 'red',
                message: err?.response?.data?.error || err?.message || 'Failed to load signing certificate validity report',
            });
        }
        finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => {
        loadReport();
    }, [loadReport]);
    const handleRunDailyCheckNow = async () => {
        setCheckLoading(true);
        try {
            const updated = await runSigningCertValidityCheckNow();
            setReport(updated);
            setBanner({
                color: updated.alertActive ? 'red' : 'teal',
                message: updated.alertActive
                    ? `Daily validity check executed: ${updated.alerts.length} expiry alert(s) detected (threshold: ${updated.alertThresholdDays} days)!`
                    : `Daily validity check executed: all ${updated.totalCount} signing certificate(s) are healthy (> ${updated.alertThresholdDays} days remaining).`,
            });
        }
        catch (err) {
            setBanner({
                color: 'red',
                message: err?.response?.data?.error || err?.message || 'Failed to execute daily validity check',
            });
        }
        finally {
            setCheckLoading(false);
        }
    };
    const openRenewalModal = (cert) => {
        setTargetCert(cert);
        setReuseExistingKey(true);
        setNewKeyLabel(`${cert.keyLabel}-renewed`);
        setCsrResult(null);
        setRenewedAlias(`${cert.alias} (Renewed)`);
        setRenewedPem('');
        setActivateRenewed(true);
        setRenewModalOpen(true);
    };
    const handleCreateRenewalCsr = async () => {
        if (!targetCert)
            return;
        setCsrLoading(true);
        try {
            const res = await createSigningCertRenewalRequest(targetCert.id, {
                reuseExistingKey,
                newKeyLabel: reuseExistingKey ? undefined : newKeyLabel.trim(),
            });
            setCsrResult(res);
        }
        catch (err) {
            setBanner({
                color: 'red',
                message: err?.response?.data?.error || err?.message || 'Failed to generate renewal CSR',
            });
        }
        finally {
            setCsrLoading(false);
        }
    };
    const handleImportRenewedCert = async () => {
        if (!targetCert || !renewedPem.trim())
            return;
        setImportLoading(true);
        try {
            const keyLabelUsed = csrResult?.keyLabel || (reuseExistingKey ? targetCert.keyLabel : newKeyLabel.trim());
            await addSigningCertificate({
                alias: renewedAlias.trim() || `${targetCert.alias} (Renewed)`,
                keyLabel: keyLabelUsed,
                certificatePem: renewedPem.trim(),
                signatureAlgorithm: targetCert.signatureAlgorithm,
                activateImmediately: activateRenewed,
            });
            setBanner({
                color: 'teal',
                message: `Renewed signing certificate '${renewedAlias}' imported${activateRenewed ? ' and activated' : ''} successfully!`,
            });
            setRenewModalOpen(false);
            await loadReport();
        }
        catch (err) {
            setBanner({
                color: 'red',
                message: err?.response?.data?.error || err?.message || 'Failed to import renewed signing certificate',
            });
        }
        finally {
            setImportLoading(false);
        }
    };
    const threshold = report?.alertThresholdDays ?? 3;
    return (<Box p="md">
      {/* Header */}
      <Group justify="space-between" align="flex-start" mb="lg">
        <div>
          <Group gap="xs">
            <IconClock size={26} color="#818cf8"/>
            <Title order={2} c="white">
              Signing Certificate Validity &amp; Renewal Monitor
            </Title>
          </Group>
          <Text c="dimmed" fz="sm" mt={4}>
            Daily scheduled validity check job (<code>{report?.dailyCron ?? '0 0 0 * * *'}</code>), {threshold}-day expiry alerting, and one-click HSM renewal CSR generation.
          </Text>
        </div>

        <Group gap="sm">
          <Button variant="default" size="sm" leftSection={<IconRefresh size={16}/>} onClick={loadReport} loading={loading}>
            Refresh
          </Button>
          <Button color="indigo" size="sm" leftSection={<IconShieldCheck size={16}/>} onClick={handleRunDailyCheckNow} loading={checkLoading}>
            Run Daily Validity Check Now
          </Button>
        </Group>
      </Group>

      {/* Action Notification Banner */}
      {banner && (<Alert color={banner.color} icon={banner.color === 'teal' ? <IconCheck size={18}/> : <IconAlertTriangle size={18}/>} withCloseButton onClose={() => setBanner(null)} radius="md" mb="md">
          {banner.message}
        </Alert>)}

      {/* CRITICAL 3-DAY EXPIRY / EXPIRED ALERT BANNER */}
      {report && report.alertActive && (<Alert color="red" variant="filled" icon={<IconAlertTriangle size={22}/>} title={`CRITICAL EXPIRY ALERT: ${report.alerts.length} Signing Certificate(s) Expiring Within ≤ ${threshold} Days or Expired`} radius="md" mb="lg">
          <Stack gap="xs" mt="xs">
            {report.alerts.map((a) => {
                const certItem = report.certificates.find((c) => c.id === a.certificateId);
                return (<Paper key={a.certificateId} p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.28)', border: '1px solid rgba(255,255,255,0.2)' }}>
                  <Group justify="space-between" wrap="wrap">
                    <div>
                      <Group gap="xs">
                        <Badge color={a.severity === 'EXPIRED' ? 'dark' : 'yellow'} variant="filled" size="sm">
                          {a.severity === 'EXPIRED' ? 'EXPIRED' : `EXPIRES IN ≤ ${threshold} DAYS`}
                        </Badge>
                        {a.active && (<Badge color="teal" variant="light" size="sm">
                            ACTIVE SIGNER
                          </Badge>)}
                        <Text fw={700} fz="sm" c="white">
                          {a.alias}
                        </Text>
                      </Group>
                      <Text fz="xs" c="gray.2" mt={4}>
                        {a.message}
                      </Text>
                    </div>
                    {certItem && (<Button size="xs" color="yellow" variant="filled" c="dark" leftSection={<IconKey size={14}/>} onClick={() => openRenewalModal(certItem)}>
                        Create Renewal Request (CSR)
                      </Button>)}
                  </Group>
                </Paper>);
            })}
          </Stack>
        </Alert>)}

      {report && !report.alertActive && report.totalCount > 0 && (<Alert color="teal" icon={<IconShieldCheck size={20}/>} title={`All Signing Certificates Valid (> ${threshold} Days Remaining)`} radius="md" mb="lg">
          <Group justify="space-between">
            <Text fz="sm">
              No signing certificates are within the {threshold}-day expiration alert window.
            </Text>
            <Text fz="xs" c="dimmed">
              Last Checked: {new Date(report.lastCheckedAt).toLocaleString()} · Daily Cron: {report.dailyCron}
            </Text>
          </Group>
        </Alert>)}

      {/* KPI Metrics */}
      <Grid mb="lg">
        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Total Signing Certs
            </Text>
            <Text fz="xl" fw={700} c="white" mt={4}>
              {report?.totalCount ?? '--'} ({report?.activeCount ?? 0} active)
            </Text>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Healthy (&gt; {threshold} Days)
            </Text>
            <Text fz="xl" fw={700} c="teal.4" mt={4}>
              {report?.healthyCount ?? '--'}
            </Text>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Expiring in ≤ {threshold} Days (Alert)
            </Text>
            <Text fz="xl" fw={700} c="yellow.4" mt={4}>
              {report?.expiringWithinThresholdCount ?? '--'}
            </Text>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
          <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
            <Text fz="xs" tt="uppercase" fw={700} c="dimmed">
              Expired
            </Text>
            <Text fz="xl" fw={700} c="red.4" mt={4}>
              {report?.expiredCount ?? '--'}
            </Text>
          </Card>
        </Grid.Col>
      </Grid>

      {/* Certificates Validity Table */}
      <Card padding="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)', border: '1px solid var(--mantine-color-dark-4)' }}>
        <Group justify="space-between" mb="md">
          <Group gap="xs">
            <IconCertificate size={20} color="#818cf8"/>
            <Text fw={700} c="white">
              Signing Certificates Validity &amp; Renewal Actions
            </Text>
          </Group>
          {report?.lastCheckedAt && (<Text fz="xs" c="dimmed">
              Last Daily Job Check: {new Date(report.lastCheckedAt).toLocaleString()}
            </Text>)}
        </Group>

        {!report || report.certificates.length === 0 ? (<Text c="dimmed" fz="sm" ta="center" py="xl">
            No signing certificates registered yet. Go to Signing Cert to generate a CSR and import your first certificate.
          </Text>) : (<Table highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Alias &amp; HSM Key</Table.Th>
                <Table.Th>Subject / Issuing CA</Table.Th>
                <Table.Th>Signer State</Table.Th>
                <Table.Th>Validity Status</Table.Th>
                <Table.Th>Expires At (notAfter)</Table.Th>
                <Table.Th>Time Remaining</Table.Th>
                <Table.Th ta="right">Renewal Action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {report.certificates.map((cert) => (<Table.Tr key={cert.id}>
                  <Table.Td>
                    <Text fw={600} fz="sm" c="white">
                      {cert.alias}
                    </Text>
                    <Group gap={6} mt={2}>
                      <Code fz={11}>{cert.keyLabel}</Code>
                      <Badge size="xs" variant="outline" color="gray">
                        {cert.signatureAlgorithm}
                      </Badge>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text fz="xs" ff="monospace" c="gray.3">
                      {cert.subjectDn}
                    </Text>
                    <Text fz="xs" c="dimmed">
                      Issuer: {cert.issuerDn}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {cert.active ? (<Badge color="teal" variant="light">
                        ACTIVE
                      </Badge>) : (<Badge color="gray" variant="light">
                        INACTIVE
                      </Badge>)}
                  </Table.Td>
                  <Table.Td>
                    {cert.validityStatus === 'EXPIRED' ? (<Badge color="red" variant="filled">
                        EXPIRED
                      </Badge>) : cert.validityStatus === 'EXPIRING_SOON' ? (<Badge color="yellow" variant="filled" c="dark">
                        ALERT: ≤ {threshold} DAYS
                      </Badge>) : (<Badge color="teal" variant="outline">
                        HEALTHY
                      </Badge>)}
                  </Table.Td>
                  <Table.Td>
                    <Text fz="xs" c="gray.3">
                      {new Date(cert.notAfter).toISOString().replace('T', ' ').substring(0, 19)} UTC
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text fz="sm" fw={700} c={cert.validityStatus === 'EXPIRED'
                    ? 'red.4'
                    : cert.validityStatus === 'EXPIRING_SOON'
                        ? 'yellow.4'
                        : 'teal.4'}>
                      {cert.expired
                    ? `Expired (${Math.abs(cert.daysUntilExpiry)}d ago)`
                    : `${cert.daysUntilExpiry}d (${cert.hoursUntilExpiry}h)`}
                    </Text>
                  </Table.Td>
                  <Table.Td ta="right">
                    <Button size="xs" variant={cert.validityStatus === 'HEALTHY' ? 'light' : 'filled'} color={cert.validityStatus === 'HEALTHY' ? 'indigo' : 'yellow'} c={cert.validityStatus === 'HEALTHY' ? undefined : 'dark'} leftSection={<IconKey size={14}/>} onClick={() => openRenewalModal(cert)}>
                      Request to Renew
                    </Button>
                  </Table.Td>
                </Table.Tr>))}
            </Table.Tbody>
          </Table>)}
      </Card>

      {/* Renewal Request (CSR) & Import Modal */}
      <Modal opened={renewModalOpen} onClose={() => setRenewModalOpen(false)} title={`Renew Signing Certificate: ${targetCert?.alias ?? ''}`} size="xl">
        {targetCert && (<Stack>
            <Paper p="sm" radius="sm" withBorder>
              <Text fz="xs" c="dimmed">
                Current Subject DN: <code>{targetCert.subjectDn}</code>
              </Text>
              <Text fz="xs" c="dimmed">
                Current HSM Key Label: <code>{targetCert.keyLabel}</code> · Algorithm: <code>{targetCert.signatureAlgorithm}</code>
              </Text>
            </Paper>

            <Switch label={`Reuse existing HSM keypair (${targetCert.keyLabel})`} description="Recommended for seamless certificate renewal without generating a new HSM slot object" checked={reuseExistingKey} onChange={(e) => setReuseExistingKey(e.currentTarget.checked)} color="teal"/>

            {!reuseExistingKey && (<TextInput label="New HSM Key Label" value={newKeyLabel} onChange={(e) => setNewKeyLabel(e.currentTarget.value)} placeholder="ocsp-signing-key-renewed" required/>)}

            <Group justify="flex-end">
              <Button leftSection={<IconKey size={16}/>} color="indigo" onClick={handleCreateRenewalCsr} loading={csrLoading}>
                1. Generate Renewal CSR from HSM
              </Button>
            </Group>

            {csrResult && (<>
                <Alert color="teal" icon={<IconCheck size={16}/>}>
                  Renewal PKCS#10 CSR generated for key <code>{csrResult.keyLabel}</code> ({csrResult.keyAlgorithm}).
                  Sign this CSR in <b>KMS Console (:3001/cas &rarr; Issue certificate &rarr; OCSP Signing)</b>, then paste the renewed certificate below.
                </Alert>

                <Box>
                  <Group justify="space-between" mb={4}>
                    <Text fz="sm" fw={600}>
                      Renewal PKCS#10 CSR (PEM)
                    </Text>
                    <Group gap={4}>
                      <CopyButton value={csrResult.csrPem}>
                        {({ copied, copy }) => (<Tooltip label={copied ? 'Copied' : 'Copy CSR'}>
                            <ActionIcon variant="subtle" onClick={copy}>
                              {copied ? <IconCheck size={16}/> : <IconCopy size={16}/>}
                            </ActionIcon>
                          </Tooltip>)}
                      </CopyButton>
                      <Tooltip label="Download .csr">
                        <ActionIcon variant="subtle" onClick={() => downloadTextFile(csrResult.csrPem, `${csrResult.keyLabel}-renewal.csr`)}>
                          <IconDownload size={16}/>
                        </ActionIcon>
                      </Tooltip>
                    </Group>
                  </Group>
                  <Code block style={{ maxHeight: 160, overflow: 'auto', fontSize: 11 }}>
                    {csrResult.csrPem}
                  </Code>
                </Box>

                <Divider my="xs" label="Step 2: Import CA-Signed Renewed Certificate" labelPosition="center"/>

                <TextInput label="New Certificate Alias" value={renewedAlias} onChange={(e) => setRenewedAlias(e.currentTarget.value)} required/>

                <Textarea label="CA-Signed Renewed Certificate (PEM)" placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'} value={renewedPem} onChange={(e) => setRenewedPem(e.currentTarget.value)} autosize minRows={4} maxRows={8} styles={{ input: { fontFamily: 'monospace', fontSize: 11 } }}/>

                <Switch label="Activate renewed certificate immediately after import" checked={activateRenewed} onChange={(e) => setActivateRenewed(e.currentTarget.checked)} color="teal"/>

                <Group justify="flex-end">
                  <Button variant="default" onClick={() => setRenewModalOpen(false)}>
                    Close
                  </Button>
                  <Button color="teal" onClick={handleImportRenewedCert} loading={importLoading} disabled={!renewedPem.trim()}>
                    2. Import &amp; Activate Renewed Certificate
                  </Button>
                </Group>
              </>)}
          </Stack>)}
      </Modal>
    </Box>);
};
