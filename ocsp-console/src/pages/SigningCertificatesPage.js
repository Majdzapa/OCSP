import React, { useState, useEffect } from 'react';
import { Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon, Modal, TextInput, Textarea, PasswordInput, Switch, Select, Alert, Loader, Tooltip, Code, Box, SimpleGrid, CopyButton, FileButton, } from '@mantine/core';
import { IconCertificate, IconPlus, IconRefresh, IconCheck, IconTrash, IconEye, IconAlertCircle, IconKey, IconShieldCheck, IconCopy, IconDownload, IconUpload, IconFileCertificate, IconCpu, IconLockOpen, } from '@tabler/icons-react';
import { getSigningCertificates, addSigningCertificate, activateSigningCertificate, deactivateSigningCertificate, deleteSigningCertificate, getHsmInfo, generateSigningCsr, activateCryptoDevice, } from '../api/client';
import { useAuth } from '../context/AuthContext';
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
export const SigningCertificatesPage = () => {
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => typeof r === 'string' ? r : (r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');
    const canOperateCsr = isAdmin || roleNames.includes('ROLE_AGENT');
    const [certificates, setCertificates] = useState([]);
    const [hsmInfo, setHsmInfo] = useState(null);
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    // Import/Add modal state
    const [addModalOpen, setAddModalOpen] = useState(false);
    const [alias, setAlias] = useState('');
    const [providerId, setProviderId] = useState('default');
    const [keyLabel, setKeyLabel] = useState('ocsp-signing-key');
    const [signatureAlgorithm, setSignatureAlgorithm] = useState('SHA256withRSA');
    const [certificatePem, setCertificatePem] = useState('');
    const [activateImmediately, setActivateImmediately] = useState(false);
    // Generate CSR modal state
    const [csrModalOpen, setCsrModalOpen] = useState(false);
    const [csrProviderId, setCsrProviderId] = useState('default');
    const [csrKeyLabel, setCsrKeyLabel] = useState('ocsp-signing-key-2');
    const [csrSubjectDn, setCsrSubjectDn] = useState('CN=Incert Delegated OCSP Signer,O=Incert,C=CH');
    const [csrAlgorithm, setCsrAlgorithm] = useState('RSA');
    const [csrKeySize, setCsrKeySize] = useState('3072');
    const [csrReuseExisting, setCsrReuseExisting] = useState(false);
    const [csrResult, setCsrResult] = useState(null);
    // View PEM modal state
    const [viewModalOpen, setViewModalOpen] = useState(false);
    const [selectedCert, setSelectedCert] = useState(null);
    // Inline quick unlock modal for LOCKED devices
    const [unlockDeviceId, setUnlockDeviceId] = useState(null);
    const [unlockPin, setUnlockPin] = useState('');
    const fetchAll = async () => {
        try {
            setLoading(true);
            setError(null);
            const [certs, hsm] = await Promise.all([
                getSigningCertificates(),
                getHsmInfo().catch(() => null),
            ]);
            setCertificates(certs);
            setHsmInfo(hsm);
            const fallbackProvider = hsm?.defaultProviderId || hsm?.providers?.[0]?.providerId || 'default';
            setProviderId((prev) => (prev === 'default' ? fallbackProvider : prev));
            setCsrProviderId((prev) => (prev === 'default' ? fallbackProvider : prev));
        }
        catch (err) {
            setError(err?.response?.data?.message || err?.message || 'Failed to load signing certificates');
        }
        finally {
            setLoading(false);
        }
    };
    useEffect(() => {
        fetchAll();
    }, []);
    const handleActivate = async (id, certAlias) => {
        try {
            setActionLoading(true);
            setError(null);
            await activateSigningCertificate(id);
            setSuccess(`Signing certificate '${certAlias}' is now active and will be selected automatically for requests from its issuing CA.`);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to activate certificate');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleDeactivate = async (id, certAlias) => {
        try {
            setActionLoading(true);
            setError(null);
            await deactivateSigningCertificate(id);
            setSuccess(`Signing certificate '${certAlias}' has been deactivated.`);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to deactivate certificate');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleDelete = async (id, certAlias) => {
        if (!window.confirm(`Are you sure you want to delete certificate '${certAlias}'?`)) {
            return;
        }
        try {
            setActionLoading(true);
            setError(null);
            await deleteSigningCertificate(id);
            setSuccess(`Certificate '${certAlias}' deleted successfully.`);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete certificate');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleAddSubmit = async (e) => {
        e.preventDefault();
        if (!alias.trim() || !certificatePem.trim()) {
            setError('Please provide both an alias and certificate PEM');
            return;
        }
        try {
            setActionLoading(true);
            setError(null);
            const payload = {
                alias: alias.trim(),
                providerId: providerId || hsmInfo?.defaultProviderId || 'default',
                keyLabel: keyLabel.trim() || 'ocsp-signing-key',
                certificatePem: certificatePem.trim(),
                activateImmediately,
                signatureAlgorithm,
            };
            await addSigningCertificate(payload);
            setSuccess(`Signing certificate '${alias}' imported into provider '${payload.providerId}' and registered${activateImmediately ? ' (activated)' : ''}.`);
            setAddModalOpen(false);
            setAlias('');
            setProviderId(hsmInfo?.defaultProviderId || hsmInfo?.providers?.[0]?.providerId || 'default');
            setKeyLabel(hsmInfo?.activeKeyLabel || 'ocsp-signing-key');
            setSignatureAlgorithm('SHA256withRSA');
            setCertificatePem('');
            setActivateImmediately(false);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to register certificate');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleGenerateCsr = async (e) => {
        e.preventDefault();
        if (!csrKeyLabel.trim() || !csrSubjectDn.trim()) {
            setError('Key label and Subject DN are required');
            return;
        }
        try {
            setActionLoading(true);
            setError(null);
            const res = await generateSigningCsr({
                providerId: csrProviderId || hsmInfo?.defaultProviderId || 'default',
                keyLabel: csrKeyLabel.trim(),
                subjectDn: csrSubjectDn.trim(),
                keyAlgorithm: csrAlgorithm,
                keySize: Number(csrKeySize),
                reuseExistingKey: csrReuseExisting,
            });
            setCsrResult(res);
            setSuccess(`CSR generated on provider '${res.providerId || csrProviderId}' for key '${res.keyLabel}'. Download the CSR, have your CA sign it, then import the certificate.`);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to generate CSR from HSM');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleFileUpload = (file) => {
        if (!file)
            return;
        const reader = new FileReader();
        reader.onload = () => {
            if (typeof reader.result === 'string') {
                setCertificatePem(reader.result);
            }
        };
        reader.readAsText(file);
    };
    const handleQuickUnlock = async (e) => {
        e.preventDefault();
        if (!unlockDeviceId || !unlockPin)
            return;
        const pinToUse = unlockPin;
        setUnlockPin('');
        try {
            setActionLoading(true);
            setError(null);
            await activateCryptoDevice(unlockDeviceId, pinToUse);
            setSuccess(`HSM device '${unlockDeviceId}' unlocked cleanly via C_Login and is now ACTIVE.`);
            setUnlockDeviceId(null);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to unlock HSM device');
        }
        finally {
            setActionLoading(false);
        }
    };
    const activeCerts = certificates.filter((c) => c.active);
    const providers = hsmInfo?.providers ?? [];
    const providerOptions = providers.map((p) => ({
        value: p.providerId,
        label: `${p.providerId} (${p.providerType}${p.tokenLabel ? ' · ' + p.tokenLabel : ''})`,
    }));
    const selectedImportProvider = providers.find((p) => p.providerId === providerId) || providers[0];
    const importKeyLabels = selectedImportProvider?.keyLabels ?? hsmInfo?.tokenAliases ?? [];
    const importKeyAlgorithms = selectedImportProvider?.keyAlgorithms ?? hsmInfo?.keyAlgorithms ?? {};
    const selectedCsrProvider = providers.find((p) => p.providerId === csrProviderId) || providers[0];
    const csrExistingKeyLabels = selectedCsrProvider?.keyLabels ?? hsmInfo?.tokenAliases ?? [];
    const rawKeyAlg = importKeyAlgorithms?.[keyLabel] || 'RSA';
    const normalizedKeyType = rawKeyAlg.toUpperCase().startsWith('EC') ? 'EC' : 'RSA';
    const compatibleAlgorithms = hsmInfo?.supportedSignatureAlgorithms?.[normalizedKeyType] ??
        (normalizedKeyType === 'EC'
            ? ['SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA']
            : ['SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA', 'SHA256withRSAandMGF1']);
    useEffect(() => {
        if (!compatibleAlgorithms.includes(signatureAlgorithm)) {
            setSignatureAlgorithm(compatibleAlgorithms[0]);
        }
    }, [normalizedKeyType, compatibleAlgorithms, signatureAlgorithm]);
    return (<Container size="xl" py="lg">
      <Stack gap="lg">
        {/* Header */}
        <Group justify="space-between" align="flex-start" wrap="wrap">
          <Box>
            <Title order={2} fw={800}>
              Signing Certificates &amp; HSM Keys
            </Title>
            <Text c="dimmed" size="sm">
              Generate CSRs directly inside the PKCS#11 HSM and activate multiple CA-signed certificates simultaneously.
              Before signing each OCSP response, the responder matches the request&apos;s issuing CA (Issuer DN &amp; Public Key hash)
              against all active signing certificates.
            </Text>
          </Box>
          <Group>
            <Button variant="default" leftSection={<IconRefresh size={16}/>} onClick={fetchAll} loading={loading}>
              Refresh
            </Button>
            {canOperateCsr && (<>
                <Button variant="light" color="cyan" leftSection={<IconFileCertificate size={16}/>} onClick={() => {
                setError(null);
                setCsrResult(null);
                setCsrModalOpen(true);
            }}>
                  Generate CSR from HSM
                </Button>
                <Button variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} leftSection={<IconPlus size={16}/>} onClick={() => {
                setError(null);
                setAddModalOpen(true);
            }}>
                  Import Signing Certificate
                </Button>
              </>)}
          </Group>
        </Group>

        {/* HSM Configuration Info Bar */}
        {hsmInfo && (<Paper withBorder p="sm" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.5)' }}>
            <Stack gap="xs">
              <Group justify="space-between" wrap="wrap" gap="sm">
                <Group gap="xs" wrap="wrap">
                  <IconCpu size={18} color="#38bdf8"/>
                  <Text size="xs" fw={700} tt="uppercase" c="dimmed">HSM Signer:</Text>
                  <Badge color={hsmInfo.signerType !== 'SOFTWARE' ? 'teal' : 'yellow'} variant="light" size="sm">
                    {hsmInfo.signerType}
                  </Badge>
                  <Text size="xs" c="dimmed">Default Device:</Text>
                  <Code>{hsmInfo.defaultProviderId || 'default'}</Code>
                  <Text size="xs" c="dimmed">Library:</Text>
                  <Code>{hsmInfo.pkcs11Library}</Code>
                  <Text size="xs" c="dimmed">Token:</Text>
                  <Code>{hsmInfo.tokenLabel} (slot {hsmInfo.slotIndex})</Code>
                </Group>
                <Badge variant="outline" color="cyan" size="xs">
                  {providers.length > 0 ? `${providers.length} Device(s) Connected` : 'Single Provider'}
                </Badge>
              </Group>

              {providers.length > 0 && (<SimpleGrid cols={{ base: 1, md: Math.min(3, providers.length) }} spacing="xs">
                  {providers.map((p) => (<Paper key={p.providerId} withBorder p="xs" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.22)' }}>
                      <Group justify="space-between" mb={4}>
                        <Group gap={6}>
                          <Badge size="xs" color={p.providerId === hsmInfo.defaultProviderId ? 'blue' : 'gray'} variant="filled">
                            {p.providerId}
                          </Badge>
                          <Badge size="xs" color="teal" variant="light">{p.providerType}</Badge>
                        </Group>
                        <Group gap={6}>
                          <Badge size="xs" color={(p.activationState || (p.healthy ? 'ACTIVE' : 'LOCKED')) === 'ACTIVE' ? 'green' : (p.activationState === 'ERROR' ? 'red' : 'orange')} variant="dot">
                            {p.activationState || (p.healthy ? 'ACTIVE' : 'LOCKED')}
                          </Badge>
                          {isAdmin && (p.activationState === 'LOCKED' || (!p.activationState && !p.healthy)) && (<Button size="compact-xs" variant="light" color="green" leftSection={<IconLockOpen size={12}/>} onClick={() => { setError(null); setUnlockPin(''); setUnlockDeviceId(p.providerId); }}>
                              Unlock
                            </Button>)}
                        </Group>
                      </Group>
                      <Text size="xs" c="dimmed">
                        Token: <Code>{p.tokenLabel || 'n/a'}</Code> · Slot <Code>{p.slotId}</Code>
                      </Text>
                      <Group gap={4} mt={4} wrap="wrap">
                        {(p.keyLabels || []).length === 0 ? (<Text size="xs" c="dimmed">No keys yet</Text>) : (p.keyLabels.map((k) => (<Badge key={k} size="xs" variant="outline" color="indigo">
                              {k}{p.keyAlgorithms?.[k] ? ` (${p.keyAlgorithms[k]})` : ''}
                            </Badge>)))}
                      </Group>
                    </Paper>))}
                </SimpleGrid>)}
            </Stack>
          </Paper>)}

        {/* Notifications */}
        {error && (<Alert icon={<IconAlertCircle size={18}/>} title="Error" color="red" withCloseButton onClose={() => setError(null)}>
            {error}
          </Alert>)}
        {success && (<Alert icon={<IconCheck size={18}/>} title="Success" color="teal" withCloseButton onClose={() => setSuccess(null)}>
            {success}
          </Alert>)}

        {/* Hero Card: Active Signing Certificates */}
        {activeCerts.length > 0 && (<Paper withBorder p="lg" radius="md" style={{
                background: 'linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(99, 102, 241, 0.08) 100%)',
                borderColor: 'rgba(34, 197, 94, 0.35)',
            }}>
            <Group justify="space-between" mb="xs">
              <Group gap="xs">
                <IconShieldCheck size={26} color="#22c55e"/>
                <Title order={3} fw={700}>
                  Active Signing Certificates ({activeCerts.length})
                </Title>
              </Group>
              <Badge color="green" size="lg" variant="filled">
                MULTI-CA ACTIVE
              </Badge>
            </Group>

            <Stack gap="sm" mt="sm">
              {activeCerts.map((cert) => (<Paper key={cert.id} withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                  <SimpleGrid cols={{ base: 1, md: 3 }} spacing="sm">
                    <Box>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Alias / Subject DN</Text>
                      <Text size="sm" fw={700}>{cert.alias}</Text>
                      <Text size="xs" c="dimmed" style={{ wordBreak: 'break-all' }}>{cert.subjectDn}</Text>
                    </Box>
                    <Box>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Issuing CA (Matched on OCSP)</Text>
                      <Text size="xs" fw={600} style={{ wordBreak: 'break-all' }}>{cert.issuerDn}</Text>
                      <Code>{cert.serialNumber}</Code>
                    </Box>
                    <Box>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Device / HSM Key / Algorithm / Expiry</Text>
                      <Group gap="xs" mt={4}>
                        <Badge variant="light" color="blue">{cert.providerId || 'default'}</Badge>
                        <Badge variant="outline" color="indigo">{cert.keyLabel}</Badge>
                        <Badge variant="light" color="cyan">{cert.signatureAlgorithm}</Badge>
                        <Badge color={cert.daysUntilExpiry < 7 ? 'red' : cert.daysUntilExpiry < 30 ? 'orange' : 'teal'} variant="light">
                          {cert.expired ? 'Expired' : `${cert.daysUntilExpiry}d left`}
                        </Badge>
                      </Group>
                    </Box>
                  </SimpleGrid>
                </Paper>))}
            </Stack>
          </Paper>)}

        {/* Certificates Table */}
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between" mb="md">
            <Title order={4}>Registered Signing Certificates ({certificates.length})</Title>
          </Group>

          {loading ? (<Group justify="center" p="xl">
              <Loader size="md"/>
            </Group>) : certificates.length === 0 ? (<Text c="dimmed" ta="center" py="xl">
              No signing certificates found in registry.
            </Text>) : (<Table.ScrollContainer minWidth={800}>
              <Table verticalSpacing="sm" highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Alias</Table.Th>
                    <Table.Th>Serial</Table.Th>
                    <Table.Th>Key Label (HSM)</Table.Th>
                    <Table.Th>Expiry / Remaining</Table.Th>
                    <Table.Th>Activated At</Table.Th>
                    <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {certificates.map((cert) => (<Table.Tr key={cert.id} style={cert.active ? { backgroundColor: 'rgba(34, 197, 94, 0.05)' } : undefined}>
                      <Table.Td>
                        {cert.active ? (<Badge color="green" variant="filled">
                            ACTIVE
                          </Badge>) : cert.expired ? (<Badge color="red" variant="light">
                            EXPIRED
                          </Badge>) : (<Badge color="gray" variant="light">
                            INACTIVE
                          </Badge>)}
                      </Table.Td>
                      <Table.Td>
                        <Text fw={600} size="sm">{cert.alias}</Text>
                        <Text size="xs" c="dimmed" lineClamp={1}>{cert.subjectDn}</Text>
                      </Table.Td>
                      <Table.Td>
                        <Code>{cert.serialNumber}</Code>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          <Badge variant="light" color="blue" size="xs">
                            {cert.providerId || 'default'}
                          </Badge>
                          <Badge variant="outline" color="indigo" size="sm">
                            {cert.keyLabel}
                          </Badge>
                          <Badge variant="light" color="cyan" size="xs">
                            {cert.signatureAlgorithm}
                          </Badge>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs">{new Date(cert.notAfter).toLocaleDateString()}</Text>
                        <Badge size="xs" color={cert.expired ? 'red' : cert.daysUntilExpiry < 7 ? 'red' : cert.daysUntilExpiry < 30 ? 'orange' : 'teal'} variant="light">
                          {cert.expired ? 'Expired' : `${cert.daysUntilExpiry}d`}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" c="dimmed">
                          {cert.activatedAt ? new Date(cert.activatedAt).toLocaleString() : 'Never'}
                        </Text>
                      </Table.Td>
                      <Table.Td style={{ textAlign: 'right' }}>
                        <Group justify="flex-end" gap="xs">
                          {isAdmin && (cert.active ? (<Button size="compact-xs" variant="light" color="orange" loading={actionLoading} disabled={activeCerts.length <= 1} onClick={() => handleDeactivate(cert.id, cert.alias)}>
                              Deactivate
                            </Button>) : (<Button size="compact-xs" variant="filled" color="green" leftSection={<IconCheck size={14}/>} loading={actionLoading} disabled={cert.expired} onClick={() => handleActivate(cert.id, cert.alias)}>
                              Activate
                            </Button>))}
                          <Tooltip label="View Certificate PEM">
                            <ActionIcon variant="light" color="blue" onClick={() => {
                    setSelectedCert(cert);
                    setViewModalOpen(true);
                }}>
                              <IconEye size={16}/>
                            </ActionIcon>
                          </Tooltip>
                          {isAdmin && !cert.active && (<Tooltip label="Delete certificate">
                              <ActionIcon variant="light" color="red" loading={actionLoading} onClick={() => handleDelete(cert.id, cert.alias)}>
                                <IconTrash size={16}/>
                              </ActionIcon>
                            </Tooltip>)}
                        </Group>
                      </Table.Td>
                    </Table.Tr>))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>)}
        </Paper>
      </Stack>

      {/* Modal: Generate CSR from HSM */}
      <Modal opened={csrModalOpen} onClose={() => setCsrModalOpen(false)} title={<Group gap="xs">
            <IconFileCertificate size={20} color="#38bdf8"/>
            <Text fw={700}>Generate PKCS#10 CSR in HSM</Text>
          </Group>} size="lg">
        {!csrResult ? (<form onSubmit={handleGenerateCsr}>
            <Stack gap="md">
              {providerOptions.length > 0 && (<Select label="Signing Device / Provider" description="Select which HSM device/token generates and stores the private key" leftSection={<IconCpu size={16}/>} data={providerOptions} value={csrProviderId} onChange={(val) => {
                    const nextProv = val || hsmInfo?.defaultProviderId || 'default';
                    setCsrProviderId(nextProv);
                    if (csrReuseExisting) {
                        const target = providers.find((p) => p.providerId === nextProv);
                        setCsrKeyLabel(target?.keyLabels?.[0] || '');
                    }
                }} required/>)}

              <Switch label="Reuse existing HSM private key" description="Enable to generate a renewal CSR using an existing key label in the selected device" checked={csrReuseExisting} onChange={(e) => {
                const checked = e.currentTarget.checked;
                setCsrReuseExisting(checked);
                if (checked && csrExistingKeyLabels.length) {
                    setCsrKeyLabel(csrExistingKeyLabels[0]);
                }
                else if (!checked) {
                    setCsrKeyLabel(`ocsp-signing-key-${certificates.length + 1}`);
                }
            }}/>

              {csrReuseExisting && csrExistingKeyLabels.length ? (<Select label="Existing HSM Key Label" data={csrExistingKeyLabels} value={csrKeyLabel} onChange={(val) => setCsrKeyLabel(val || '')} required/>) : (<TextInput label="New HSM Key Label" placeholder="ocsp-signing-key-2" description="A non-extractable keypair will be generated inside the selected HSM token under this label" leftSection={<IconKey size={16}/>} value={csrKeyLabel} onChange={(e) => setCsrKeyLabel(e.currentTarget.value)} required/>)}

              <TextInput label="Subject Distinguished Name (DN)" placeholder="CN=Incert Delegated OCSP Signer,O=Incert,C=CH" value={csrSubjectDn} onChange={(e) => setCsrSubjectDn(e.currentTarget.value)} required/>

              {!csrReuseExisting && (<SimpleGrid cols={2}>
                  <Select label="Key Algorithm" data={[
                    { value: 'RSA', label: 'RSA' },
                    { value: 'EC', label: 'ECDSA (Elliptic Curve)' },
                ]} value={csrAlgorithm} onChange={(val) => {
                    const alg = val || 'RSA';
                    setCsrAlgorithm(alg);
                    setCsrKeySize(alg === 'EC' ? '256' : '3072');
                }}/>
                  <Select label="Key Size / Curve" data={csrAlgorithm === 'EC'
                    ? [
                        { value: '256', label: 'P-256 (secp256r1)' },
                        { value: '384', label: 'P-384 (secp384r1)' },
                    ]
                    : [
                        { value: '2048', label: '2048 bits' },
                        { value: '3072', label: '3072 bits (Recommended)' },
                        { value: '4096', label: '4096 bits' },
                    ]} value={csrKeySize} onChange={(val) => setCsrKeySize(val || '3072')}/>
                </SimpleGrid>)}

              <Group justify="flex-end" mt="md">
                <Button variant="default" onClick={() => setCsrModalOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" color="cyan" loading={actionLoading} leftSection={<IconFileCertificate size={16}/>}>
                  Generate CSR
                </Button>
              </Group>
            </Stack>
          </form>) : (<Stack gap="md">
            <Alert color="teal" icon={<IconCheck size={18}/>} title="CSR Generated & Signed by HSM">
              Key label <Code>{csrResult.keyLabel}</Code> is stored in the HSM token. Submit this CSR to your CA
              (with <Code>OCSPSigning</Code> EKU), then import the signed certificate using key label <Code>{csrResult.keyLabel}</Code>.
            </Alert>

            <Group justify="space-between">
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">PKCS#10 CSR (PEM)</Text>
              <Group gap="xs">
                <CopyButton value={csrResult.csrPem}>
                  {({ copied, copy }) => (<Button size="xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={14}/>} onClick={copy}>
                      {copied ? 'Copied' : 'Copy CSR'}
                    </Button>)}
                </CopyButton>
                <Button size="xs" variant="filled" color="cyan" leftSection={<IconDownload size={14}/>} onClick={() => downloadTextFile(csrResult.csrPem, `${csrResult.keyLabel}.csr.pem`)}>
                  Download .csr
                </Button>
              </Group>
            </Group>

            <Code block style={{ maxHeight: 260, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
              {csrResult.csrPem}
            </Code>

            <Group justify="space-between" mt="sm">
              <Button variant="light" color="indigo" onClick={() => {
                if (csrResult.providerId) {
                    setProviderId(csrResult.providerId);
                }
                setKeyLabel(csrResult.keyLabel);
                setAlias(csrResult.keyLabel);
                setCsrModalOpen(false);
                setAddModalOpen(true);
            }}>
                Import Signed Certificate for '{csrResult.keyLabel}'
              </Button>
              <Button variant="default" onClick={() => setCsrModalOpen(false)}>
                Close
              </Button>
            </Group>
          </Stack>)}
      </Modal>

      {/* Modal: Import / Add Signing Certificate */}
      <Modal opened={addModalOpen} onClose={() => setAddModalOpen(false)} title={<Group gap="xs">
            <IconCertificate size={20} color="#6366f1"/>
            <Text fw={700}>Import Signing Certificate</Text>
          </Group>} size="lg">
        <form onSubmit={handleAddSubmit}>
          <Stack gap="md">
            <TextInput label="Certificate Alias" placeholder="e.g. ocsp-signing-2027" value={alias} onChange={(e) => setAlias(e.currentTarget.value)} required/>

            {providerOptions.length > 0 && (<Select label="Signing Device / Provider" description="Device holding the corresponding private key" leftSection={<IconCpu size={16}/>} data={providerOptions} value={providerId} onChange={(val) => {
                const nextProv = val || hsmInfo?.defaultProviderId || 'default';
                setProviderId(nextProv);
                const target = providers.find((p) => p.providerId === nextProv);
                if (target?.keyLabels?.length) {
                    setKeyLabel(target.keyLabels[0]);
                }
            }} required/>)}

            {importKeyLabels.length ? (<Select label="HSM Key Label / Alias" description={`Detected key type for '${keyLabel}': ${normalizedKeyType}`} leftSection={<IconKey size={16}/>} data={importKeyLabels.map((a) => ({
                value: a,
                label: importKeyAlgorithms?.[a] ? `${a} (${importKeyAlgorithms[a]})` : a,
            }))} value={keyLabel} onChange={(val) => setKeyLabel(val || importKeyLabels[0])} searchable required/>) : (<TextInput label="HSM Key Label / Alias" placeholder="ocsp-signing-key" description="The private key label in the HSM token corresponding to this certificate" leftSection={<IconKey size={16}/>} value={keyLabel} onChange={(e) => setKeyLabel(e.currentTarget.value)} required/>)}

            <Select label="Signature Algorithm" description={`Compatible algorithms for ${normalizedKeyType} key '${keyLabel}'`} data={compatibleAlgorithms.map((alg) => ({ value: alg, label: alg }))} value={signatureAlgorithm} onChange={(val) => setSignatureAlgorithm(val || compatibleAlgorithms[0])} required/>

            <Group justify="space-between" align="flex-end">
              <Text size="sm" fw={500}>Certificate PEM</Text>
              <FileButton onChange={handleFileUpload} accept=".pem,.crt,.cer">
                {(props) => (<Button {...props} size="xs" variant="light" leftSection={<IconUpload size={14}/>}>
                    Upload .pem / .crt File
                  </Button>)}
              </FileButton>
            </Group>

            <Textarea placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----" description="Paste or upload the CA-signed X.509 signing certificate in PEM format" minRows={6} maxRows={10} value={certificatePem} onChange={(e) => setCertificatePem(e.currentTarget.value)} required/>

            {isAdmin && (<Switch label="Make active immediately" description="If checked, this certificate will immediately become the active signer for all OCSP responses (otherwise kept in standby)" checked={activateImmediately} onChange={(e) => setActivateImmediately(e.currentTarget.checked)} color="green"/>)}

            <Group justify="flex-end" mt="md">
              <Button variant="default" onClick={() => setAddModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} loading={actionLoading}>
                Import Certificate
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* Modal: View PEM */}
      <Modal opened={viewModalOpen} onClose={() => setViewModalOpen(false)} title={<Group justify="space-between" style={{ width: '100%' }}>
            <Text fw={700}>Certificate PEM: {selectedCert?.alias}</Text>
            {selectedCert && (<Group gap="xs">
                <CopyButton value={selectedCert.certificatePem}>
                  {({ copied, copy }) => (<Button size="xs" color={copied ? 'teal' : 'indigo'} variant="light" leftSection={<IconCopy size={14}/>} onClick={copy}>
                      {copied ? 'Copied' : 'Copy PEM'}
                    </Button>)}
                </CopyButton>
                <Button size="xs" variant="light" color="cyan" leftSection={<IconDownload size={14}/>} onClick={() => downloadTextFile(selectedCert.certificatePem, `${selectedCert.alias}.crt.pem`)}>
                  Download
                </Button>
              </Group>)}
          </Group>} size="lg">
        {selectedCert && (<Stack gap="sm">
            <Box p="xs" style={{ borderRadius: 6, backgroundColor: 'rgba(0,0,0,0.2)' }}>
              <Text size="xs" c="dimmed">Subject: <b>{selectedCert.subjectDn}</b></Text>
              <Text size="xs" c="dimmed">Issuer: <b>{selectedCert.issuerDn}</b></Text>
              <Text size="xs" c="dimmed">Serial: <code>{selectedCert.serialNumber}</code></Text>
            </Box>
            <Code block style={{ maxHeight: 300, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
              {selectedCert.certificatePem}
            </Code>
          </Stack>)}
      </Modal>

      {/* Modal: Quick Unlock LOCKED Device */}
      <Modal opened={Boolean(unlockDeviceId)} onClose={() => { setUnlockPin(''); setUnlockDeviceId(null); }} title={<Group gap="xs"><IconLockOpen size={20} color="#22c55e"/><Text fw={700}>Unlock HSM Device: {unlockDeviceId}</Text></Group>}>
        <form onSubmit={handleQuickUnlock}>
          <Stack gap="md">
            <Alert color="cyan" variant="light">
              Enter the token user PIN for <Code>{unlockDeviceId}</Code>. PIN is used once for <Code>C_Login</Code> and immediately wiped from memory.
            </Alert>
            <PasswordInput label="PKCS#11 User PIN" placeholder="Enter PIN" value={unlockPin} onChange={(e) => setUnlockPin(e.currentTarget.value)} autoFocus required/>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => { setUnlockPin(''); setUnlockDeviceId(null); }}>Cancel</Button>
              <Button type="submit" color="green" loading={actionLoading} leftSection={<IconLockOpen size={16}/>}>Unlock</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Container>);
};
