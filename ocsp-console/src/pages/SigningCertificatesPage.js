import React, { useState, useEffect } from 'react';
import { Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon, Modal, TextInput, Textarea, PasswordInput, Switch, Select, Alert, Loader, Tooltip, Code, Box, SimpleGrid, CopyButton, FileButton, } from '@mantine/core';
import { IconCertificate, IconPlus, IconRefresh, IconCheck, IconTrash, IconEye, IconAlertCircle, IconKey, IconShieldCheck, IconCopy, IconDownload, IconUpload, IconFileCertificate, IconCpu, IconLockOpen, IconSearch, IconX, } from '@tabler/icons-react';
import { getSigningCertificates, addSigningCertificate, activateSigningCertificate, deactivateSigningCertificate, deleteSigningCertificate, getHsmInfo, getProviderCapabilities, checkSigningAlgorithm, generateSigningCsr, activateCryptoDevice, getSigners, importSignerCertificate, generateSignerCsr, } from '../api/client';
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
    const [signers, setSigners] = useState([]);
    const [hsmInfo, setHsmInfo] = useState(null);
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    // Import/Add modal state (select Signer -> import into Signer via POST /signer/{id}/cert)
    const [addModalOpen, setAddModalOpen] = useState(false);
    const [selectedSignerId, setSelectedSignerId] = useState('');
    const [alias, setAlias] = useState('');
    const [providerId, setProviderId] = useState('default');
    const [keyLabel, setKeyLabel] = useState('ocsp-signing-key');
    const [signatureAlgorithm, setSignatureAlgorithm] = useState('');
    const [certificatePem, setCertificatePem] = useState('');
    const [activateImmediately, setActivateImmediately] = useState(false);
    const [importCapabilities, setImportCapabilities] = useState(null);
    const [importAlgCheck, setImportAlgCheck] = useState(null);
    // Generate CSR modal state
    const [csrModalOpen, setCsrModalOpen] = useState(false);
    const [csrSignerId, setCsrSignerId] = useState('');
    const [csrProviderId, setCsrProviderId] = useState('default');
    const [csrKeyLabel, setCsrKeyLabel] = useState('ocsp-signing-key-2');
    const [csrSubjectDn, setCsrSubjectDn] = useState('CN=Incert Delegated OCSP Signer,O=Incert,C=CH');
    const [csrAlgorithm, setCsrAlgorithm] = useState('');
    const [csrKeySize, setCsrKeySize] = useState('');
    const [csrSignatureAlgorithm, setCsrSignatureAlgorithm] = useState('');
    const [csrReuseExisting, setCsrReuseExisting] = useState(false);
    const [csrResult, setCsrResult] = useState(null);
    const [csrCapabilities, setCsrCapabilities] = useState(null);
    const [csrAlgCheck, setCsrAlgCheck] = useState(null);
    // Interactive Algorithm Support Checker modal state
    const [checkModalOpen, setCheckModalOpen] = useState(false);
    const [checkProviderId, setCheckProviderId] = useState('default');
    const [checkKeyLabel, setCheckKeyLabel] = useState('');
    const [checkKeyAlgorithm, setCheckKeyAlgorithm] = useState('');
    const [checkKeySize, setCheckKeySize] = useState('');
    const [checkSigAlgorithm, setCheckSigAlgorithm] = useState('');
    const [checkCapabilities, setCheckCapabilities] = useState(null);
    const [checkResult, setCheckResult] = useState(null);
    const [checkLoading, setCheckLoading] = useState(false);
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
            const [certs, hsm, signerList] = await Promise.all([
                getSigningCertificates(),
                getHsmInfo().catch(() => null),
                getSigners().catch(() => []),
            ]);
            setCertificates(certs);
            setHsmInfo(hsm);
            setSigners(signerList || []);
            if (signerList?.length > 0) {
                const firstSigner = signerList[0];
                setSelectedSignerId((prev) => (prev && signerList.some((s) => String(s.id) === String(prev)) ? prev : String(firstSigner.id)));
                setCsrSignerId((prev) => (prev && signerList.some((s) => String(s.id) === String(prev)) ? prev : String(firstSigner.id)));
            }
            const fallbackProvider = hsm?.defaultProviderId || hsm?.providers?.[0]?.providerId || 'default';
            setProviderId((prev) => (prev === 'default' ? fallbackProvider : prev));
            setCsrProviderId((prev) => (prev === 'default' ? fallbackProvider : prev));
            setCheckProviderId((prev) => (prev === 'default' ? fallbackProvider : prev));
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
        if (!selectedSignerId) {
            setError('Please select an OCSP Signer first (or create one under OCSP Signers)');
            return;
        }
        if (!certificatePem.trim()) {
            setError('Please provide the certificate PEM');
            return;
        }
        const targetSigner = signers.find((s) => String(s.id) === String(selectedSignerId));
        try {
            setActionLoading(true);
            setError(null);
            const updated = await importSignerCertificate(Number(selectedSignerId), {
                certificatePem: certificatePem.trim(),
                signatureAlgorithm: signatureAlgorithm || targetSigner?.signatureAlgorithm || null,
                activateImmediately,
            });
            setSuccess(`Signing certificate imported into Signer '${updated.name}' (${updated.code})${activateImmediately ? ' and activated' : ''}.`);
            setAddModalOpen(false);
            setCertificatePem('');
            setActivateImmediately(false);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to import certificate into signer');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleGenerateCsr = async (e) => {
        e.preventDefault();
        if (!csrSignerId) {
            setError('Please select an OCSP Signer first');
            return;
        }
        try {
            setActionLoading(true);
            setError(null);
            const res = await generateSignerCsr(Number(csrSignerId), {});
            setCsrResult(res);
            setSelectedSignerId(String(csrSignerId));
            setSuccess(`Key '${res.keyLabel}' & CSR generated for Signer '${res.signerCode}' on HSM Vslot '${res.vslotDeviceId}'.`);
            await fetchAll();
        }
        catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to generate CSR from Signer');
        }
        finally {
            setActionLoading(false);
        }
    };
    const handleRunAlgorithmCheck = async (e) => {
        if (e) e.preventDefault();
        try {
            setCheckLoading(true);
            const res = await checkSigningAlgorithm({
                providerId: checkProviderId || hsmInfo?.defaultProviderId || 'default',
                keyLabel: checkKeyLabel.trim() || null,
                keyAlgorithm: checkKeyLabel.trim() ? null : (checkKeyAlgorithm || null),
                keySize: checkKeyLabel.trim() ? null : (checkKeySize ? Number(checkKeySize) : null),
                signatureAlgorithm: checkSigAlgorithm.trim() || null,
            });
            setCheckResult(res);
        } catch (err) {
            setCheckResult({
                supported: false,
                message: err?.response?.data?.error || err?.message || 'Failed to check algorithm support',
            });
        } finally {
            setCheckLoading(false);
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
    const csrKeyAlgorithms = selectedCsrProvider?.keyAlgorithms ?? hsmInfo?.keyAlgorithms ?? {};
    const selectedCheckProvider = providers.find((p) => p.providerId === checkProviderId) || providers[0];
    const checkExistingKeyLabels = selectedCheckProvider?.keyLabels ?? [];

    // Load live HSM capabilities whenever the CSR modal is open or its provider changes
    useEffect(() => {
        if (!csrModalOpen || !csrProviderId) return;
        let cancelled = false;
        getProviderCapabilities(csrProviderId)
            .then((caps) => {
                if (cancelled) return;
                setCsrCapabilities(caps);
                const firstKeyCap = (caps.keyAlgorithms || []).find((k) => k.supported) || caps.keyAlgorithms?.[0];
                if (!csrReuseExisting && firstKeyCap) {
                    setCsrAlgorithm((prev) => {
                        const valid = (caps.keyAlgorithms || []).some((k) => k.keyAlgorithm === prev);
                        return valid ? prev : firstKeyCap.keyAlgorithm;
                    });
                }
            })
            .catch(() => { if (!cancelled) setCsrCapabilities(null); });
        return () => { cancelled = true; };
    }, [csrModalOpen, csrProviderId, csrReuseExisting]);

    const csrEffectiveKeyType = csrReuseExisting
        ? ((csrKeyAlgorithms?.[csrKeyLabel] || '').toUpperCase().startsWith('EC') ? 'EC' : (csrKeyAlgorithms?.[csrKeyLabel] ? 'RSA' : ''))
        : csrAlgorithm;
    const csrSelectedKeyCap = (csrCapabilities?.keyAlgorithms || []).find((k) => k.keyAlgorithm === csrAlgorithm);
    const csrAvailableKeySizes = csrSelectedKeyCap?.supportedKeySizes ?? [];
    const csrSigCaps = (csrCapabilities?.signatureAlgorithms || []).filter(
        (s) => !csrEffectiveKeyType || s.keyType === csrEffectiveKeyType
    );

    // Sync CSR key size & signature algorithm when key algorithm or capabilities change
    useEffect(() => {
        if (!csrReuseExisting && csrAvailableKeySizes.length > 0 && !csrAvailableKeySizes.includes(Number(csrKeySize))) {
            const preferred = csrAvailableKeySizes.includes(3072) ? 3072 : csrAvailableKeySizes[0];
            setCsrKeySize(String(preferred));
        }
    }, [csrReuseExisting, csrAlgorithm, csrCapabilities]);

    useEffect(() => {
        if (csrSigCaps.length > 0 && !csrSigCaps.some((s) => s.algorithm === csrSignatureAlgorithm)) {
            const firstSupported = csrSigCaps.find((s) => s.supported) || csrSigCaps[0];
            setCsrSignatureAlgorithm(firstSupported?.algorithm || '');
        }
    }, [csrEffectiveKeyType, csrCapabilities]);

    // Live pre-signing check inside CSR modal
    useEffect(() => {
        if (!csrModalOpen || !csrProviderId || !csrSignatureAlgorithm) {
            setCsrAlgCheck(null);
            return;
        }
        let cancelled = false;
        checkSigningAlgorithm({
            providerId: csrProviderId,
            keyLabel: csrReuseExisting ? csrKeyLabel : null,
            keyAlgorithm: csrReuseExisting ? null : (csrAlgorithm || null),
            keySize: csrReuseExisting ? null : (csrKeySize ? Number(csrKeySize) : null),
            signatureAlgorithm: csrSignatureAlgorithm,
        }).then((res) => { if (!cancelled) setCsrAlgCheck(res); })
          .catch(() => { if (!cancelled) setCsrAlgCheck(null); });
        return () => { cancelled = true; };
    }, [csrModalOpen, csrProviderId, csrReuseExisting, csrKeyLabel, csrAlgorithm, csrKeySize, csrSignatureAlgorithm]);

    // Load live HSM capabilities whenever the Import modal is open or its provider changes
    useEffect(() => {
        if (!addModalOpen || !providerId) return;
        let cancelled = false;
        getProviderCapabilities(providerId)
            .then((caps) => { if (!cancelled) setImportCapabilities(caps); })
            .catch(() => { if (!cancelled) setImportCapabilities(null); });
        return () => { cancelled = true; };
    }, [addModalOpen, providerId]);

    const rawKeyAlg = importKeyAlgorithms?.[keyLabel] || '';
    const normalizedKeyType = rawKeyAlg ? (rawKeyAlg.toUpperCase().startsWith('EC') ? 'EC' : 'RSA') : '';
    const importSigCaps = (importCapabilities?.signatureAlgorithms || []).filter(
        (s) => !normalizedKeyType || s.keyType === normalizedKeyType
    );
    const importAlgOptions = importSigCaps.length > 0
        ? importSigCaps.map((s) => ({
            value: s.algorithm,
            label: s.supported ? `${s.algorithm} — ✓ Supported (${s.mechanismName})` : `${s.algorithm} — ✗ Unsupported (${s.mechanismName})`,
        }))
        : Object.entries(hsmInfo?.supportedSignatureAlgorithms || {})
            .filter(([kt]) => !normalizedKeyType || kt === normalizedKeyType)
            .flatMap(([, algs]) => algs)
            .map((alg) => ({ value: alg, label: alg }));

    useEffect(() => {
        if (importAlgOptions.length > 0 && !importAlgOptions.some((o) => o.value === signatureAlgorithm)) {
            const firstSupported = importSigCaps.find((s) => s.supported)?.algorithm || importAlgOptions[0].value;
            setSignatureAlgorithm(firstSupported);
        }
    }, [normalizedKeyType, importCapabilities, hsmInfo]);

    // Live pre-import algorithm verification
    useEffect(() => {
        if (!addModalOpen || !providerId || !signatureAlgorithm) {
            setImportAlgCheck(null);
            return;
        }
        let cancelled = false;
        checkSigningAlgorithm({
            providerId,
            keyLabel: keyLabel.trim() || null,
            keyAlgorithm: normalizedKeyType || null,
            keySize: null,
            signatureAlgorithm,
        }).then((res) => { if (!cancelled) setImportAlgCheck(res); })
          .catch(() => { if (!cancelled) setImportAlgCheck(null); });
        return () => { cancelled = true; };
    }, [addModalOpen, providerId, keyLabel, normalizedKeyType, signatureAlgorithm]);

    // Load live HSM capabilities whenever the Algorithm Checker modal opens or provider changes
    useEffect(() => {
        if (!checkModalOpen || !checkProviderId) return;
        let cancelled = false;
        getProviderCapabilities(checkProviderId)
            .then((caps) => { if (!cancelled) setCheckCapabilities(caps); })
            .catch(() => { if (!cancelled) setCheckCapabilities(null); });
        return () => { cancelled = true; };
    }, [checkModalOpen, checkProviderId]);

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
              Key and signing algorithms are queried live from each HSM via <Code>C_GetMechanismList</Code> and validated before signing.
            </Text>
          </Box>
          <Group>
            <Button variant="default" leftSection={<IconRefresh size={16}/>} onClick={fetchAll} loading={loading}>
              Refresh
            </Button>
            <Button variant="light" color="teal" leftSection={<IconSearch size={16}/>} onClick={() => {
                setCheckResult(null);
                setCheckModalOpen(true);
            }}>
              Check Algorithm Support
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

      {/* Modal: Generate CSR for Signer */}
      <Modal opened={csrModalOpen} onClose={() => setCsrModalOpen(false)} title={<Group gap="xs">
            <IconFileCertificate size={20} color="#38bdf8"/>
            <Text fw={700}>Generate PKCS#10 CSR for OCSP Signer</Text>
          </Group>} size="lg">
        {!csrResult ? (<form onSubmit={handleGenerateCsr}>
            <Stack gap="md">
              {signers.length === 0 ? (
                <Alert color="orange" icon={<IconAlertCircle size={16}/>} title="No OCSP Signers Configured">
                  Please create an OCSP Signer first on the <b>OCSP Signers</b> page. Each Signer already holds its UUID code, UUID HSM key label, ordered HSM Vslots, and signature algorithm.
                </Alert>
              ) : (
                <>
                  <Select
                    label="OCSP Signer"
                    description="Select the OCSP Signer for which to generate the HSM keypair and PKCS#10 CSR"
                    leftSection={<IconKey size={16}/>}
                    data={signers.map((s) => ({
                        value: String(s.id),
                        label: `${s.name} (${s.code} · ${s.keyAlgorithm} ${s.keySize} · ${s.signatureAlgorithm})`,
                    }))}
                    value={csrSignerId}
                    onChange={(val) => setCsrSignerId(val || '')}
                    searchable
                    required
                  />
                  {(() => {
                      const s = signers.find((item) => String(item.id) === String(csrSignerId));
                      if (!s) return null;
                      return (
                        <Paper withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.22)' }}>
                          <Stack gap={4}>
                            <Group justify="space-between">
                              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Signer Summary</Text>
                              <Badge size="xs" color="indigo">{s.status}</Badge>
                            </Group>
                            <Text size="xs">Signer Code (UUID): <Code>{s.code}</Code></Text>
                            <Text size="xs">HSM Key Label (UUID): <Code>{s.keyLabel}</Code></Text>
                            <Text size="xs">Subject DN: <Code>{s.subjectDn}</Code></Text>
                            <Text size="xs">Algorithm: <Code>{s.keyAlgorithm} {s.keySize}</Code> · <Code>{s.signatureAlgorithm}</Code></Text>
                            <Text size="xs">Bound HSM Vslots: {(s.vslots || []).map((v) => `${v.deviceId} (${v.role})`).join(', ')}</Text>
                          </Stack>
                        </Paper>
                      );
                  })()}
                </>
              )}

              <Group justify="flex-end" mt="md">
                <Button variant="default" onClick={() => setCsrModalOpen(false)}>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  color="cyan"
                  loading={actionLoading}
                  disabled={!csrSignerId || signers.length === 0}
                  leftSection={<IconFileCertificate size={16}/>}
                >
                  Generate Key &amp; CSR
                </Button>
              </Group>
            </Stack>
          </form>) : (<Stack gap="md">
            <Alert color="teal" icon={<IconCheck size={18}/>} title="CSR Generated & Signed by HSM">
              Key label <Code>{csrResult.keyLabel}</Code> is stored in HSM Vslot <Code>{csrResult.vslotDeviceId}</Code>. Submit this CSR to your CA
              (with <Code>OCSPSigning</Code> EKU), then import the signed certificate into Signer <Code>{csrResult.signerCode}</Code>.
            </Alert>

            <Group justify="space-between">
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">PKCS#10 CSR (PEM)</Text>
              <Group gap="xs">
                <CopyButton value={csrResult.csrPem}>
                  {({ copied, copy }) => (<Button size="xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={14}/>} onClick={copy}>
                      {copied ? 'Copied' : 'Copy CSR'}
                    </Button>)}
                </CopyButton>
                <Button size="xs" variant="filled" color="cyan" leftSection={<IconDownload size={14}/>} onClick={() => downloadTextFile(csrResult.csrPem, `${csrResult.signerCode || csrResult.keyLabel}.csr.pem`)}>
                  Download .csr
                </Button>
              </Group>
            </Group>

            <Code block style={{ maxHeight: 260, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
              {csrResult.csrPem}
            </Code>

            <Group justify="space-between" mt="sm">
              <Button variant="light" color="indigo" onClick={() => {
                setSelectedSignerId(String(csrResult.signerId || csrSignerId));
                setCsrModalOpen(false);
                setAddModalOpen(true);
            }}>
                Import Signed Certificate into Signer
              </Button>
              <Button variant="default" onClick={() => setCsrModalOpen(false)}>
                Close
              </Button>
            </Group>
          </Stack>)}
      </Modal>

      {/* Modal: Import Signing Certificate into Signer */}
      <Modal opened={addModalOpen} onClose={() => setAddModalOpen(false)} title={<Group gap="xs">
            <IconCertificate size={20} color="#6366f1"/>
            <Text fw={700}>Import Signing Certificate into Signer</Text>
          </Group>} size="lg">
        <form onSubmit={handleAddSubmit}>
          <Stack gap="md">
            {signers.length === 0 ? (
              <Alert color="orange" icon={<IconAlertCircle size={16}/>} title="No OCSP Signers Configured">
                Please create an OCSP Signer first on the <b>OCSP Signers</b> page.
              </Alert>
            ) : (
              <>
                <Select
                  label="Select OCSP Signer"
                  description="The certificate will be imported and bound directly to this Signer's HSM Vslots and UUID key label"
                  leftSection={<IconKey size={16}/>}
                  data={signers.map((s) => ({
                      value: String(s.id),
                      label: `${s.name} (${s.code})`,
                  }))}
                  value={selectedSignerId}
                  onChange={(val) => setSelectedSignerId(val || '')}
                  searchable
                  required
                />

                {(() => {
                    const s = signers.find((item) => String(item.id) === String(selectedSignerId));
                    if (!s) return null;
                    return (
                      <Paper withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.22)' }}>
                        <Stack gap={4}>
                          <Group justify="space-between">
                            <Text size="xs" c="dimmed" fw={700} tt="uppercase">Bound Signer Configuration</Text>
                            <Badge size="xs" color="teal">{s.signatureAlgorithm}</Badge>
                          </Group>
                          <Text size="xs">Signer Code (UUID): <Code>{s.code}</Code></Text>
                          <Text size="xs">HSM Private Key Label (UUID): <Code>{s.keyLabel}</Code> ({s.keyAlgorithm} {s.keySize})</Text>
                          <Text size="xs">HSM Vslots: {(s.vslots || []).map((v) => `${v.deviceId} [${v.role} · ${v.activationState}]`).join(', ')}</Text>
                        </Stack>
                      </Paper>
                    );
                })()}
              </>
            )}

            <Group justify="space-between" align="flex-end">
              <Text size="sm" fw={500}>Certificate PEM</Text>
              <FileButton onChange={handleFileUpload} accept=".pem,.crt,.cer">
                {(props) => (<Button {...props} size="xs" variant="light" leftSection={<IconUpload size={14}/>}>
                    Upload .pem / .crt File
                  </Button>)}
              </FileButton>
            </Group>

            <Textarea placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----" description="Paste or upload the CA-signed X.509 signing certificate in PEM format" minRows={6} maxRows={10} value={certificatePem} onChange={(e) => setCertificatePem(e.currentTarget.value)} required/>

            {isAdmin && (<Switch label="Activate signer immediately" description="If checked, this signer and its certificate will immediately become active for OCSP responses" checked={activateImmediately} onChange={(e) => setActivateImmediately(e.currentTarget.checked)} color="green"/>)}

            <Group justify="flex-end" mt="md">
              <Button variant="default" onClick={() => setAddModalOpen(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                variant="gradient"
                gradient={{ from: 'indigo.6', to: 'violet.6' }}
                loading={actionLoading}
                disabled={!selectedSignerId || signers.length === 0}
              >
                Import Certificate into Signer
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

      {/* Modal: Interactive HSM Algorithm Support Checker */}
      <Modal
        opened={checkModalOpen}
        onClose={() => setCheckModalOpen(false)}
        title={<Group gap="xs"><IconSearch size={20} color="#14b8a6"/><Text fw={700}>Check HSM Key &amp; Signing Algorithm Support</Text></Group>}
        size="lg"
      >
        <form onSubmit={handleRunAlgorithmCheck}>
          <Stack gap="md">
            {providerOptions.length > 0 && (
              <Select
                label="HSM Device / Provider"
                data={providerOptions}
                value={checkProviderId}
                onChange={(val) => {
                    setCheckProviderId(val || hsmInfo?.defaultProviderId || 'default');
                    setCheckKeyLabel('');
                    setCheckResult(null);
                }}
                required
              />
            )}

            {checkCapabilities && (
              <Alert
                color={checkCapabilities.liveIntrospected ? 'cyan' : 'orange'}
                variant="light"
                title={checkCapabilities.liveIntrospected ? 'Live HSM Capabilities (C_GetMechanismList)' : 'Device Not Unlocked'}
              >
                {checkCapabilities.statusMessage}
              </Alert>
            )}

            <Select
              label="Existing HSM Key Label (optional)"
              description="Pick an existing key to check its actual hardware key type, or leave blank to test a key algorithm + size"
              placeholder="None — test key algorithm directly"
              clearable
              data={checkExistingKeyLabels.map((k) => ({
                  value: k,
                  label: selectedCheckProvider?.keyAlgorithms?.[k] ? `${k} (${selectedCheckProvider.keyAlgorithms[k]})` : k,
              }))}
              value={checkKeyLabel || null}
              onChange={(val) => { setCheckKeyLabel(val || ''); setCheckResult(null); }}
            />

            {!checkKeyLabel && (
              <SimpleGrid cols={2}>
                <TextInput
                  label="Key Algorithm"
                  placeholder="e.g. RSA, EC, Ed25519"
                  description="Enter or pick any key algorithm to test"
                  value={checkKeyAlgorithm}
                  onChange={(e) => { setCheckKeyAlgorithm(e.currentTarget.value); setCheckResult(null); }}
                />
                <TextInput
                  label="Key Size (bits, optional)"
                  placeholder="e.g. 2048, 3072, 4096, 256, 384"
                  value={checkKeySize}
                  onChange={(e) => { setCheckKeySize(e.currentTarget.value); setCheckResult(null); }}
                />
              </SimpleGrid>
            )}

            <TextInput
              label="Signing Algorithm to Verify"
              placeholder="e.g. SHA256withRSA, SHA384withRSA, SHA256withRSAandMGF1, SHA384withECDSA"
              description="Enter any signature algorithm name to check against live HSM mechanisms before signing"
              value={checkSigAlgorithm}
              onChange={(e) => { setCheckSigAlgorithm(e.currentTarget.value); setCheckResult(null); }}
            />

            {checkResult && (
              <Alert
                color={checkResult.supported ? 'teal' : 'red'}
                icon={checkResult.supported ? <IconCheck size={18}/> : <IconX size={18}/>}
                title={checkResult.supported ? 'SUPPORTED BY HSM' : 'NOT SUPPORTED'}
              >
                <Stack gap={4}>
                  <Text size="sm">{checkResult.message}</Text>
                  {checkResult.requiredMechanism && (
                    <Text size="xs" c="dimmed">Required PKCS#11 mechanism: <Code>{checkResult.requiredMechanism}</Code></Text>
                  )}
                  {checkResult.compatibleSupportedAlgorithms?.length > 0 && (
                    <Group gap={4} mt={4} wrap="wrap">
                      <Text size="xs" c="dimmed">Supported alternatives:</Text>
                      {checkResult.compatibleSupportedAlgorithms.map((a) => (
                        <Badge key={a} size="xs" variant="light" color="teal" style={{ cursor: 'pointer' }} onClick={() => setCheckSigAlgorithm(a)}>
                          {a}
                        </Badge>
                      ))}
                    </Group>
                  )}
                </Stack>
              </Alert>
            )}

            {checkCapabilities?.liveIntrospected && (
              <Paper withBorder p="xs" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                <Text size="xs" fw={700} tt="uppercase" c="dimmed" mb={6}>Live HSM Mechanism Matrix</Text>
                <Group gap={6} wrap="wrap" mb={6}>
                  {(checkCapabilities.keyAlgorithms || []).map((k) => (
                    <Badge key={k.keyAlgorithm} size="xs" color={k.supported ? 'teal' : 'red'} variant="light">
                      {k.supported ? '✓' : '✗'} {k.keyAlgorithm}{k.supportedKeySizes?.length ? ` [${k.supportedKeySizes.join('/')}]` : ''}
                    </Badge>
                  ))}
                </Group>
                <Group gap={6} wrap="wrap">
                  {(checkCapabilities.signatureAlgorithms || []).map((s) => (
                    <Badge
                      key={s.algorithm}
                      size="xs"
                      color={s.supported ? 'cyan' : 'red'}
                      variant="outline"
                      style={{ cursor: 'pointer' }}
                      onClick={() => setCheckSigAlgorithm(s.algorithm)}
                    >
                      {s.supported ? '✓' : '✗'} {s.algorithm} ({s.mechanismName})
                    </Badge>
                  ))}
                </Group>
              </Paper>
            )}

            <Group justify="flex-end">
              <Button variant="default" onClick={() => setCheckModalOpen(false)}>Close</Button>
              <Button type="submit" color="teal" loading={checkLoading} leftSection={<IconSearch size={16}/>}>
                Check Support
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Container>);
};
