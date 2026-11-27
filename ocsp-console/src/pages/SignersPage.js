import React, { useState, useEffect, useCallback } from 'react';
import {
    Container, Paper, Title, Text, Group, Stack, Button, Badge, ActionIcon,
    Modal, TextInput, Textarea, PasswordInput, Select, MultiSelect, Switch,
    Alert, Loader, Tooltip, Code, Box, SimpleGrid, CopyButton, FileButton, Divider,
} from '@mantine/core';
import {
    IconKey, IconPlus, IconRefresh, IconCheck, IconTrash, IconEdit, IconEye,
    IconAlertCircle, IconLockOpen, IconFileCertificate, IconCertificate,
    IconCopy, IconDownload, IconUpload, IconX,
} from '@tabler/icons-react';
import {
    getSigners, getOcspKeys, createSigner, updateSigner, deleteSigner,
    generateSignerCsr, getSignerCsr, getSignerCertificate, importSignerCertificate,
    activateSigner, deactivateSigner, getCryptoDevices, activateCryptoDevice,
    getProviderCapabilities, checkSigningAlgorithm,
} from '../api/client';
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

function generateUuid() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}

export const SignersPage = () => {
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => typeof r === 'string' ? r : (r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');
    const canOperate = isAdmin || roleNames.includes('ROLE_AGENT');

    const [signers, setSigners] = useState([]);
    const [keys, setKeys] = useState([]);
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    // Create / Edit Signer modal
    const [formOpen, setFormOpen] = useState(false);
    const [editingId, setEditingId] = useState(null);
    const [code, setCode] = useState('');
    const [name, setName] = useState('');
    const [subjectDn, setSubjectDn] = useState('CN=Incert Delegated OCSP Signer,O=Incert,C=LU');
    const [useExistingKey, setUseExistingKey] = useState(false);
    const [selectedKeyId, setSelectedKeyId] = useState('');
    const [keyLabel, setKeyLabel] = useState('');
    const [keyAlgorithm, setKeyAlgorithm] = useState('RSA');
    const [keySize, setKeySize] = useState('3072');
    const [signatureAlgorithm, setSignatureAlgorithm] = useState('SHA256withRSA');
    const [tokenIds, setTokenIds] = useState([]);
    const [capabilities, setCapabilities] = useState(null);
    const [algCheck, setAlgCheck] = useState(null);

    // Public Key viewer modal (from ocsp_keys — 0 HSM calls)
    const [viewKeyModal, setViewKeyModal] = useState(null);

    // CSR modal (GET / POST /signer/{id}/csr)
    const [csrModalSigner, setCsrModalSigner] = useState(null);
    const [csrData, setCsrData] = useState(null);
    const [csrLoading, setCsrLoading] = useState(false);

    // Certificate modal (GET / POST /signer/{id}/cert)
    const [certModalSigner, setCertModalSigner] = useState(null);
    const [certData, setCertData] = useState(null);
    const [certPemInput, setCertPemInput] = useState('');
    const [certActivateNow, setCertActivateNow] = useState(true);
    const [certLoading, setCertLoading] = useState(false);

    // Quick Unlock modal for LOCKED HSM Tokens
    const [unlockDeviceId, setUnlockDeviceId] = useState(null);
    const [unlockPin, setUnlockPin] = useState('');

    const fetchAll = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const [sList, kList, dList] = await Promise.all([
                getSigners(),
                getOcspKeys().catch(() => []),
                getCryptoDevices().catch(() => []),
            ]);
            setSigners(sList);
            setKeys(kList);
            setDevices(dList);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load OCSP Signers');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAll();
    }, [fetchAll]);

    const primaryTokenId = tokenIds[0] || '';

    // Load cached HSM capabilities for the primary selected Token
    useEffect(() => {
        if (!formOpen || !primaryTokenId) {
            setCapabilities(null);
            return;
        }
        let cancelled = false;
        getProviderCapabilities(primaryTokenId)
            .then((caps) => { if (!cancelled) setCapabilities(caps); })
            .catch(() => { if (!cancelled) setCapabilities(null); });
        return () => { cancelled = true; };
    }, [formOpen, primaryTokenId]);

    // Pre-verify key + signature algorithm against the primary Token's cached mechanism list (0 token object scans)
    useEffect(() => {
        if (!formOpen || !primaryTokenId || !signatureAlgorithm) {
            setAlgCheck(null);
            return;
        }
        let cancelled = false;
        checkSigningAlgorithm({
            providerId: primaryTokenId,
            keyLabel: null,
            keyAlgorithm,
            keySize: keySize ? Number(keySize) : null,
            signatureAlgorithm,
        })
            .then((res) => { if (!cancelled) setAlgCheck(res); })
            .catch(() => { if (!cancelled) setAlgCheck(null); });
        return () => { cancelled = true; };
    }, [formOpen, primaryTokenId, keyAlgorithm, keySize, signatureAlgorithm]);

    const openCreate = () => {
        setEditingId(null);
        const nextIdx = signers.length + 1;
        setCode(generateUuid());
        setName(`OCSP Delegated Signer ${nextIdx}`);
        setSubjectDn('CN=Incert Delegated OCSP Signer,O=Incert,C=LU');
        setUseExistingKey(false);
        setSelectedKeyId('');
        setKeyLabel(generateUuid());
        setKeyAlgorithm('RSA');
        setKeySize('3072');
        setSignatureAlgorithm('SHA256withRSA');
        const defaultDev = devices.find((d) => d.isDefault) || devices[0];
        setTokenIds(defaultDev ? [defaultDev.deviceId] : []);
        setError(null);
        setFormOpen(true);
    };

    const openEdit = (s) => {
        setEditingId(s.id);
        setCode(s.code);
        setName(s.name);
        setSubjectDn(s.subjectDn);
        if (s.keyId != null) {
            setUseExistingKey(true);
            setSelectedKeyId(String(s.keyId));
        } else {
            setUseExistingKey(false);
            setSelectedKeyId('');
        }
        setKeyLabel(s.keyLabel);
        setKeyAlgorithm(s.keyAlgorithm || 'RSA');
        setKeySize(String(s.keySize || 3072));
        setSignatureAlgorithm(s.signatureAlgorithm || 'SHA256withRSA');
        setTokenIds((s.tokens || []).map((t) => t.deviceId));
        setError(null);
        setFormOpen(true);
    };

    const handleSaveSigner = async (e) => {
        e.preventDefault();
        if (tokenIds.length === 0) {
            setError('Select at least one HSM Token for this signer');
            return;
        }
        if (useExistingKey && !selectedKeyId) {
            setError('Select an existing cryptographic key from ocsp_keys');
            return;
        }
        try {
            setSaving(true);
            setError(null);
            const payload = {
                code: code.trim(),
                name: name.trim(),
                subjectDn: subjectDn.trim(),
                keyId: useExistingKey && selectedKeyId ? Number(selectedKeyId) : null,
                keyLabel: useExistingKey ? null : keyLabel.trim(),
                keyAlgorithm,
                keySize: Number(keySize),
                signatureAlgorithm,
                tokenDeviceIds: tokenIds,
            };
            if (editingId != null) {
                await updateSigner(editingId, payload);
                setSuccess(`Signer '${payload.code}' updated.`);
            } else {
                await createSigner(payload);
                setSuccess(`Signer '${payload.code}' created with ${tokenIds.length} HSM Token(s).`);
            }
            setFormOpen(false);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to save OCSP Signer');
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteSigner = async (s) => {
        if (!window.confirm(`Delete OCSP Signer '${s.code}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteSigner(s.id);
            setSuccess(`Signer '${s.code}' deleted.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete signer');
        } finally {
            setSaving(false);
        }
    };

    // ---- CSR Workflow (GET /signer/{id}/csr & POST /signer/{id}/csr) ----
    const openCsrModal = async (s, generateNow = false) => {
        setCsrModalSigner(s);
        setCsrData(null);
        setError(null);
        try {
            setCsrLoading(true);
            if (generateNow || !s.hasCsr) {
                const reqBody = s.hasCsr ? { reuseExistingKey: false } : {};
                const generated = await generateSignerCsr(s.id, reqBody);
                setCsrData(generated);
                setSuccess(`Generated key '${generated.keyLabel}' (Key #${generated.keyId ?? 'new'} in ocsp_keys) & signed CSR on Token '${generated.tokenDeviceId}'.`);
                await fetchAll();
            } else {
                const existing = await getSignerCsr(s.id, false);
                setCsrData(existing);
            }
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to generate/load CSR');
        } finally {
            setCsrLoading(false);
        }
    };

    // ---- Certificate Workflow (GET /signer/{id}/cert & POST /signer/{id}/cert — 0 HSM Token Calls) ----
    const openCertModal = async (s) => {
        setCertModalSigner(s);
        setCertData(null);
        setCertPemInput('');
        setCertActivateNow(isAdmin);
        setError(null);
        if (s.hasCertificate) {
            try {
                setCertLoading(true);
                const existing = await getSignerCertificate(s.id);
                setCertData(existing);
            } catch {
                setCertData(s.certificate || null);
            } finally {
                setCertLoading(false);
            }
        }
    };

    const handleImportCert = async (e) => {
        e.preventDefault();
        if (!certModalSigner || !certPemInput.trim()) return;
        try {
            setCertLoading(true);
            setError(null);
            const updated = await importSignerCertificate(certModalSigner.id, {
                certificatePem: certPemInput.trim(),
                signatureAlgorithm: certModalSigner.signatureAlgorithm,
                activateImmediately: isAdmin ? certActivateNow : false,
            });
            setCertData(updated.certificate);
            setCertPemInput('');
            setSuccess(`Imported X.509 certificate (serial ${updated.certificate?.serialNumber}) into signer '${updated.code}' (verified against ocsp_keys with zero HSM token calls).`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to import certificate into signer');
        } finally {
            setCertLoading(false);
        }
    };

    const handleCertFileUpload = (file) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            if (typeof reader.result === 'string') setCertPemInput(reader.result);
        };
        reader.readAsText(file);
    };

    const handleToggleActive = async (s) => {
        try {
            setSaving(true);
            setError(null);
            if (s.active) {
                await deactivateSigner(s.id);
                setSuccess(`Signer '${s.code}' deactivated.`);
            } else {
                await activateSigner(s.id);
                setSuccess(`Signer '${s.code}' activated for live RFC 6960 OCSP signing.`);
            }
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to toggle signer state');
        } finally {
            setSaving(false);
        }
    };

    const handleQuickUnlock = async (e) => {
        e.preventDefault();
        if (!unlockDeviceId || !unlockPin) return;
        const pin = unlockPin;
        setUnlockPin('');
        try {
            setSaving(true);
            setError(null);
            await activateCryptoDevice(unlockDeviceId, pin);
            setUnlockDeviceId(null);
            setSuccess(`HSM Token '${unlockDeviceId}' unlocked via C_Login.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to unlock HSM Token');
        } finally {
            setSaving(false);
        }
    };

    const tokenOptions = devices.map((d) => ({
        value: d.deviceId,
        label: `${d.deviceId} (${d.providerCode} · token: ${d.tokenLabel || 'slot ' + d.slotId} · ${d.activationState})`,
    }));

    const existingKeyOptions = keys.map((k) => ({
        value: String(k.id),
        label: `Key #${k.id} · ${k.keyLabel} (${k.keyAlgorithm} ${k.keySize}${k.tokenDeviceCode ? ' · ' + k.tokenDeviceCode : ''})`,
    }));

    const keyCapList = capabilities?.keyAlgorithms || [];
    const keyAlgOptions = keyCapList.length > 0
        ? keyCapList.map((k) => ({
            value: k.keyAlgorithm,
            label: k.supported ? `${k.keyAlgorithm} — ✓ Supported (${k.mechanismName})` : `${k.keyAlgorithm} — ✗ Unsupported`,
        }))
        : [{ value: 'RSA', label: 'RSA' }, { value: 'EC', label: 'EC (ECDSA)' }];

    const selectedKeyCap = keyCapList.find((k) => k.keyAlgorithm === keyAlgorithm);
    const keySizeList = selectedKeyCap?.supportedKeySizes?.length
        ? selectedKeyCap.supportedKeySizes
        : (keyAlgorithm === 'EC' ? [256, 384, 521] : [2048, 3072, 4096]);
    const keySizeOptions = keySizeList.map((b) => ({
        value: String(b),
        label: keyAlgorithm === 'EC' ? `P-${b} (${b} bits)` : `${b} bits`,
    }));

    const sigCapList = (capabilities?.signatureAlgorithms || []).filter((s) => s.keyType === keyAlgorithm);
    const sigAlgOptions = sigCapList.length > 0
        ? sigCapList.map((s) => ({
            value: s.algorithm,
            label: s.supported ? `${s.algorithm} — ✓ Supported (${s.mechanismName})` : `${s.algorithm} — ✗ Unsupported (${s.mechanismName})`,
        }))
        : (keyAlgorithm === 'EC'
            ? ['SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA']
            : ['SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA', 'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1']
        ).map((a) => ({ value: a, label: a }));

    const statusBadgeColor = (status) => {
        if (status === 'ACTIVE') return 'green';
        if (status === 'CERT_IMPORTED') return 'teal';
        if (status === 'CSR_GENERATED') return 'cyan';
        if (status === 'EXPIRED') return 'red';
        return 'gray';
    };

    return (
        <Container size="xl" py="md">
            <Stack gap="md">
                <Group justify="space-between" align="flex-start" wrap="wrap">
                    <Box>
                        <Group gap="xs">
                            <IconKey size={26} color="#818cf8" />
                            <Title order={2} c="white">OCSP Signers</Title>
                            <Badge color="indigo" variant="light">KEY ENTITY · TOKENS · CSR · CERT</Badge>
                        </Group>
                        <Text c="dimmed" size="sm" mt={2}>
                            Unified Signer aggregate linking persisted Keys (<Code>ocsp_keys</Code>) and ordered HSM Tokens (<Code>ocsp_signer_tokens</Code>).
                            Hardware tokens are touched <b>only</b> during keygen/CSR (<Code>POST /signer/&#123;id&#125;/csr</Code>) and live OCSP signing (<Code>POST /ocsp</Code>).
                        </Text>
                    </Box>
                    <Group gap="xs">
                        <Button variant="default" size="sm" leftSection={<IconRefresh size={15} />} onClick={fetchAll} loading={loading}>
                            Refresh
                        </Button>
                        {canOperate && (
                            <Button variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} size="sm" leftSection={<IconPlus size={15} />} onClick={openCreate}>
                                New OCSP Signer
                            </Button>
                        )}
                    </Group>
                </Group>

                {error && (
                    <Alert icon={<IconAlertCircle size={18} />} title="Error" color="red" withCloseButton onClose={() => setError(null)}>
                        {error}
                    </Alert>
                )}
                {success && (
                    <Alert icon={<IconCheck size={18} />} title="Success" color="teal" withCloseButton onClose={() => setSuccess(null)}>
                        {success}
                    </Alert>
                )}

                {loading ? (
                    <Group justify="center" p="xl"><Loader size="md" /></Group>
                ) : signers.length === 0 ? (
                    <Paper withBorder p="xl" radius="md" ta="center">
                        <Text c="dimmed" mb="md">No OCSP Signers configured yet.</Text>
                        {canOperate && (
                            <Button variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} leftSection={<IconPlus size={15} />} onClick={openCreate}>
                                Create First OCSP Signer
                            </Button>
                        )}
                    </Paper>
                ) : (
                    <Stack gap="md">
                        {signers.map((s) => (
                            <Paper
                                key={s.id}
                                withBorder
                                p="md"
                                radius="md"
                                style={{
                                    backgroundColor: 'rgba(15, 23, 42, 0.5)',
                                    borderColor: s.active ? 'rgba(34, 197, 94, 0.45)' : undefined,
                                }}
                            >
                                <Stack gap="sm">
                                    {/* Top Row: Identity + Lifecycle Badges + Actions */}
                                    <Group justify="space-between" wrap="wrap" gap="xs">
                                        <Group gap="xs">
                                            <Badge size="md" color={statusBadgeColor(s.status)} variant="filled">
                                                {s.status}
                                            </Badge>
                                            <Text fw={700} fz="md" c="white">{s.name}</Text>
                                            <Code>{s.code}</Code>
                                            <Badge size="xs" color="gray" variant="outline">ID #{s.id}</Badge>
                                        </Group>
                                        <Group gap="xs" wrap="wrap">
                                            <Button
                                                size="compact-xs"
                                                variant={s.hasCsr ? 'light' : 'filled'}
                                                color="cyan"
                                                leftSection={<IconFileCertificate size={14} />}
                                                onClick={() => openCsrModal(s, !s.hasCsr)}
                                            >
                                                {s.hasCsr ? 'View / Re-gen Key & CSR' : '1. Generate Key & CSR'}
                                            </Button>
                                            <Button
                                                size="compact-xs"
                                                variant={s.hasCertificate ? 'light' : 'filled'}
                                                color="indigo"
                                                leftSection={<IconCertificate size={14} />}
                                                onClick={() => openCertModal(s)}
                                            >
                                                {s.hasCertificate ? 'View / Replace Cert' : '2. Import Certificate'}
                                            </Button>
                                            {isAdmin && s.hasCertificate && (
                                                <Button
                                                    size="compact-xs"
                                                    variant={s.active ? 'light' : 'filled'}
                                                    color={s.active ? 'orange' : 'green'}
                                                    leftSection={<IconCheck size={14} />}
                                                    loading={saving}
                                                    onClick={() => handleToggleActive(s)}
                                                >
                                                    {s.active ? 'Deactivate' : '3. Activate Signer'}
                                                </Button>
                                            )}
                                            {canOperate && (
                                                <Tooltip label="Edit signer, Key & Tokens">
                                                    <ActionIcon variant="light" color="blue" onClick={() => openEdit(s)}>
                                                        <IconEdit size={15} />
                                                    </ActionIcon>
                                                </Tooltip>
                                            )}
                                            {isAdmin && !s.active && (
                                                <Tooltip label="Delete signer">
                                                    <ActionIcon variant="light" color="red" onClick={() => handleDeleteSigner(s)}>
                                                        <IconTrash size={15} />
                                                    </ActionIcon>
                                                </Tooltip>
                                            )}
                                        </Group>
                                    </Group>

                                    {/* Middle Row: Key Entity (ocsp_keys) + Bound HSM Tokens (ocsp_signer_tokens) + Certificate */}
                                    <SimpleGrid cols={{ base: 1, md: 3 }} spacing="sm">
                                        <Paper withBorder p="xs" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                                            <Group justify="space-between">
                                                <Text size="10px" c="dimmed" tt="uppercase" fw={700}>Key Entity (ocsp_keys)</Text>
                                                {s.key ? (
                                                    <Group gap={4}>
                                                        <Badge size="xs" color="teal" variant="light">KEY #{s.key.id}</Badge>
                                                        <Tooltip label="View persisted Public Key SPKI (0 HSM calls)">
                                                            <ActionIcon size="xs" variant="subtle" color="cyan" onClick={() => setViewKeyModal(s.key)}>
                                                                <IconEye size={13} />
                                                            </ActionIcon>
                                                        </Tooltip>
                                                    </Group>
                                                ) : (
                                                    <Badge size="xs" color="gray" variant="outline">PENDING KEYGEN</Badge>
                                                )}
                                            </Group>
                                            <Group gap={6} mt={4} wrap="wrap">
                                                <Badge size="xs" color="indigo" variant="outline">{s.keyLabel}</Badge>
                                                <Badge size="xs" color="cyan" variant="light">{s.keyAlgorithm} {s.keySize}</Badge>
                                                <Badge size="xs" color="teal" variant="light">{s.signatureAlgorithm}</Badge>
                                            </Group>
                                            {s.key?.publicKeySha1 && (
                                                <Text size="11px" c="dimmed" mt={4} lineClamp={1}>
                                                    Key SHA-1: <Code>{s.key.publicKeySha1}</Code>
                                                </Text>
                                            )}
                                            <Text size="xs" c="dimmed" mt={2} lineClamp={1}>DN: {s.subjectDn}</Text>
                                        </Paper>

                                        <Paper withBorder p="xs" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                                            <Text size="10px" c="dimmed" tt="uppercase" fw={700}>HSM Tokens ({(s.tokens || []).length})</Text>
                                            <Stack gap={4} mt={4}>
                                                {(s.tokens || []).map((t) => (
                                                    <Group key={t.deviceId} justify="space-between" gap={4} wrap="nowrap">
                                                        <Group gap={4} wrap="nowrap">
                                                            <Badge size="xs" color={t.role === 'PRIMARY' ? 'blue' : 'gray'} variant="filled">
                                                                {t.role}
                                                            </Badge>
                                                            <Code>{t.deviceId}</Code>
                                                            <Text size="11px" c="dimmed">({t.tokenLabel || `slot ${t.slotId}`})</Text>
                                                        </Group>
                                                        <Group gap={4} wrap="nowrap">
                                                            {t.keyRegistered && <Badge size="xs" color="teal" variant="outline">KEY BOUND</Badge>}
                                                            <Badge size="xs" color={t.activationState === 'ACTIVE' ? 'green' : 'orange'} variant="dot">
                                                                {t.activationState}
                                                            </Badge>
                                                            {isAdmin && t.activationState !== 'ACTIVE' && (
                                                                <Button size="compact-xs" variant="subtle" color="green" onClick={() => { setUnlockPin(''); setUnlockDeviceId(t.deviceId); }}>
                                                                    Unlock
                                                                </Button>
                                                            )}
                                                        </Group>
                                                    </Group>
                                                ))}
                                            </Stack>
                                        </Paper>

                                        <Paper withBorder p="xs" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                                            <Text size="10px" c="dimmed" tt="uppercase" fw={700}>CSR &amp; X.509 Certificate</Text>
                                            {s.certificate ? (
                                                <Stack gap={2} mt={4}>
                                                    <Group gap={6}>
                                                        <Badge size="xs" color={s.certificate.expired ? 'red' : 'teal'} variant="light">
                                                            {s.certificate.expired ? 'EXPIRED' : `${s.certificate.daysUntilExpiry}d remaining`}
                                                        </Badge>
                                                        <Code>{s.certificate.serialNumber}</Code>
                                                    </Group>
                                                    <Text size="xs" c="dimmed" lineClamp={1}>Issuer: {s.certificate.issuerDn}</Text>
                                                </Stack>
                                            ) : s.hasCsr ? (
                                                <Text size="xs" c="cyan.3" mt={6}>
                                                    CSR generated — sign with your CA and click <b>Import Certificate</b> (0 HSM calls).
                                                </Text>
                                            ) : (
                                                <Text size="xs" c="dimmed" mt={6}>
                                                    No CSR or certificate yet — click <b>Generate Key &amp; CSR</b>.
                                                </Text>
                                            )}
                                        </Paper>
                                    </SimpleGrid>
                                </Stack>
                            </Paper>
                        ))}
                    </Stack>
                )}
            </Stack>

            {/* Modal: Create / Edit Signer */}
            <Modal
                opened={formOpen}
                onClose={() => setFormOpen(false)}
                title={<Group gap="xs"><IconKey size={20} color="#818cf8" /><Text fw={700}>{editingId != null ? 'Edit OCSP Signer' : 'New OCSP Signer'}</Text></Group>}
                size="lg"
            >
                <form onSubmit={handleSaveSigner}>
                    <Stack gap="md">
                        <SimpleGrid cols={2}>
                            <TextInput
                                label="Signer Code (UUID)"
                                description="Auto-generated UUID identifier"
                                value={code}
                                onChange={(e) => setCode(e.currentTarget.value)}
                                rightSection={editingId == null && (
                                    <Tooltip label="Generate new UUID">
                                        <ActionIcon variant="subtle" size="sm" onClick={() => setCode(generateUuid())}>
                                            <IconRefresh size={14} />
                                        </ActionIcon>
                                    </Tooltip>
                                )}
                                required
                            />
                            <TextInput label="Display Name" placeholder="Luxembourg Root CA Signer" value={name} onChange={(e) => setName(e.currentTarget.value)} required />
                        </SimpleGrid>

                        <MultiSelect
                            label="Bound HSM Tokens (ocsp_signer_tokens: 1st = PRIMARY, others = FAILOVER)"
                            description="Attach one or more PKCS#11 HSM Tokens. Live OCSP signing fails over across unlocked tokens."
                            placeholder="Select HSM Token(s)"
                            data={tokenOptions}
                            value={tokenIds}
                            onChange={setTokenIds}
                            searchable
                            required
                        />

                        {keys.length > 0 && (
                            <Switch
                                label="Bind an existing cryptographic key from ocsp_keys (e.g. for certificate renewal)"
                                checked={useExistingKey}
                                onChange={(e) => {
                                    const checked = e.currentTarget.checked;
                                    setUseExistingKey(checked);
                                    if (checked && keys.length > 0) {
                                        const first = keys[0];
                                        setSelectedKeyId(String(first.id));
                                        setKeyAlgorithm(first.keyAlgorithm);
                                        setKeySize(String(first.keySize));
                                        setSignatureAlgorithm(first.keyAlgorithm === 'EC' ? 'SHA256withECDSA' : 'SHA256withRSA');
                                    }
                                }}
                            />
                        )}

                        {useExistingKey ? (
                            <SimpleGrid cols={2}>
                                <Select
                                    label="Persisted Key (ocsp_keys)"
                                    description="Metadata loaded from DB (zero HSM calls)"
                                    data={existingKeyOptions}
                                    value={selectedKeyId}
                                    onChange={(val) => {
                                        setSelectedKeyId(val || '');
                                        const k = keys.find((item) => String(item.id) === String(val));
                                        if (k) {
                                            setKeyAlgorithm(k.keyAlgorithm);
                                            setKeySize(String(k.keySize));
                                            setSignatureAlgorithm(k.keyAlgorithm === 'EC' ? 'SHA256withECDSA' : 'SHA256withRSA');
                                        }
                                    }}
                                    searchable
                                    required
                                />
                                <TextInput label="Subject Distinguished Name (DN)" placeholder="CN=Incert OCSP Signer,O=Incert,C=LU" value={subjectDn} onChange={(e) => setSubjectDn(e.currentTarget.value)} required />
                            </SimpleGrid>
                        ) : (
                            <SimpleGrid cols={2}>
                                <TextInput
                                    label="HSM Private Key Label (UUID)"
                                    description="Created on token & persisted to ocsp_keys when CSR is generated"
                                    value={keyLabel}
                                    onChange={(e) => setKeyLabel(e.currentTarget.value)}
                                    rightSection={editingId == null && (
                                        <Tooltip label="Generate new UUID">
                                            <ActionIcon variant="subtle" size="sm" onClick={() => setKeyLabel(generateUuid())}>
                                                <IconRefresh size={14} />
                                            </ActionIcon>
                                        </Tooltip>
                                    )}
                                    required
                                />
                                <TextInput label="Subject Distinguished Name (DN)" placeholder="CN=Incert OCSP Signer,O=Incert,C=LU" value={subjectDn} onChange={(e) => setSubjectDn(e.currentTarget.value)} required />
                            </SimpleGrid>
                        )}

                        <SimpleGrid cols={3}>
                            <Select
                                label="Key Algorithm"
                                data={keyAlgOptions}
                                value={keyAlgorithm}
                                disabled={useExistingKey}
                                onChange={(val) => {
                                    const nextAlg = val || 'RSA';
                                    setKeyAlgorithm(nextAlg);
                                    setKeySize(nextAlg === 'EC' ? '256' : '3072');
                                    setSignatureAlgorithm(nextAlg === 'EC' ? 'SHA256withECDSA' : 'SHA256withRSA');
                                }}
                                required
                            />
                            <Select
                                label="Key Size / Curve"
                                data={keySizeOptions}
                                value={keySize}
                                disabled={useExistingKey}
                                onChange={(val) => setKeySize(val || '3072')}
                                required
                            />
                            <Select
                                label="Signature Algorithm"
                                data={sigAlgOptions}
                                value={signatureAlgorithm}
                                onChange={(val) => setSignatureAlgorithm(val || '')}
                                required
                            />
                        </SimpleGrid>

                        {algCheck && (
                            <Alert
                                color={algCheck.supported ? 'teal' : 'red'}
                                icon={algCheck.supported ? <IconCheck size={16} /> : <IconX size={16} />}
                                title={algCheck.supported ? 'Verified Against Primary HSM Token' : 'Unsupported by Primary HSM Token'}
                            >
                                {algCheck.message}
                            </Alert>
                        )}

                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setFormOpen(false)}>Cancel</Button>
                            <Button type="submit" loading={saving} disabled={algCheck != null && !algCheck.supported}>
                                Save Signer
                            </Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            {/* Modal: View Persisted Public Key (ocsp_keys — 0 HSM calls) */}
            <Modal
                opened={Boolean(viewKeyModal)}
                onClose={() => setViewKeyModal(null)}
                title={<Group gap="xs"><IconKey size={20} color="#2dd4bf" /><Text fw={700}>Key Entity #{viewKeyModal?.id}: {viewKeyModal?.keyLabel}</Text></Group>}
                size="lg"
            >
                {viewKeyModal && (
                    <Stack gap="sm">
                        <Alert color="teal" variant="light">
                            Loaded from <Code>ocsp_keys</Code> in MariaDB (zero PKCS#11 token calls). Private key remains non-extractable inside HSM Token <Code>{viewKeyModal.tokenDeviceCode || 'HSM'}</Code>.
                        </Alert>
                        <Text size="xs">Algorithm: <Code>{viewKeyModal.keyAlgorithm} {viewKeyModal.keySize}</Code> · Public Key SHA-1 (SKI): <Code>{viewKeyModal.publicKeySha1}</Code></Text>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" fw={700}>SubjectPublicKeyInfo (PEM)</Text>
                            <CopyButton value={viewKeyModal.publicKeyPem}>
                                {({ copied, copy }) => (
                                    <Button size="compact-xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={13} />} onClick={copy}>
                                        {copied ? 'Copied' : 'Copy Public Key'}
                                    </Button>
                                )}
                            </CopyButton>
                        </Group>
                        <Code block style={{ maxHeight: 240, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {viewKeyModal.publicKeyPem}
                        </Code>
                    </Stack>
                )}
            </Modal>

            {/* Modal: View / Generate CSR (GET & POST /signer/{id}/csr) */}
            <Modal
                opened={Boolean(csrModalSigner)}
                onClose={() => { setCsrModalSigner(null); setCsrData(null); }}
                title={<Group gap="xs"><IconFileCertificate size={20} color="#38bdf8" /><Text fw={700}>Signer CSR: {csrModalSigner?.code}</Text></Group>}
                size="lg"
            >
                {csrLoading ? (
                    <Group justify="center" p="xl"><Loader size="md" /></Group>
                ) : csrData ? (
                    <Stack gap="md">
                        <Alert color="teal" variant="light">
                            Generated on HSM Token <Code>{csrData.tokenDeviceId}</Code> · Key <Code>{csrData.keyLabel}</Code> ({csrData.keyAlgorithm} {csrData.keySize}) · Algorithm <Code>{csrData.signatureAlgorithm}</Code>
                        </Alert>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" fw={700}>GET /api/v1/admin/signer/{csrModalSigner?.id}/csr</Text>
                            <Group gap="xs">
                                <CopyButton value={csrData.csrPem}>
                                    {({ copied, copy }) => (
                                        <Button size="xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={14} />} onClick={copy}>
                                            {copied ? 'Copied' : 'Copy CSR'}
                                        </Button>
                                    )}
                                </CopyButton>
                                <Button size="xs" variant="filled" color="cyan" leftSection={<IconDownload size={14} />} onClick={() => downloadTextFile(csrData.csrPem, `${csrModalSigner.code}.csr.pem`)}>
                                    Download .csr
                                </Button>
                                {canOperate && (
                                    <Button size="xs" variant="subtle" color="orange" leftSection={<IconRefresh size={14} />} onClick={() => openCsrModal(csrModalSigner, true)}>
                                        Re-generate New Key &amp; CSR
                                    </Button>
                                )}
                            </Group>
                        </Group>
                        <Code block style={{ maxHeight: 280, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {csrData.csrPem}
                        </Code>
                        <Group justify="space-between">
                            <Button
                                variant="light"
                                color="indigo"
                                leftSection={<IconCertificate size={15} />}
                                onClick={() => {
                                    const target = csrModalSigner;
                                    setCsrModalSigner(null);
                                    openCertModal(target);
                                }}
                            >
                                Proceed to Import Signed Certificate
                            </Button>
                            <Button variant="default" onClick={() => setCsrModalSigner(null)}>Close</Button>
                        </Group>
                    </Stack>
                ) : (
                    <Stack gap="md">
                        <Text size="sm" c="dimmed">No CSR generated yet for this signer.</Text>
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setCsrModalSigner(null)}>Close</Button>
                            {canOperate && (
                                <Button color="cyan" onClick={() => openCsrModal(csrModalSigner, true)}>
                                    Generate Key &amp; CSR Now
                                </Button>
                            )}
                        </Group>
                    </Stack>
                )}
            </Modal>

            {/* Modal: View / Import Certificate (GET & POST /signer/{id}/cert — 0 HSM calls) */}
            <Modal
                opened={Boolean(certModalSigner)}
                onClose={() => { setCertModalSigner(null); setCertData(null); setCertPemInput(''); }}
                title={<Group gap="xs"><IconCertificate size={20} color="#6366f1" /><Text fw={700}>Signer Certificate: {certModalSigner?.code}</Text></Group>}
                size="lg"
            >
                <Stack gap="md">
                    {certLoading ? (
                        <Group justify="center" p="md"><Loader size="sm" /></Group>
                    ) : certData ? (
                        <Paper withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.22)' }}>
                            <Group justify="space-between" mb={6}>
                                <Group gap="xs">
                                    <Badge color={certData.expired ? 'red' : 'teal'} variant="filled">
                                        {certData.expired ? 'EXPIRED' : `VALID (${certData.daysUntilExpiry}d left)`}
                                    </Badge>
                                    <Code>{certData.serialNumber}</Code>
                                    <Badge color="cyan" variant="light">{certData.signatureAlgorithm}</Badge>
                                </Group>
                                <Group gap="xs">
                                    <CopyButton value={certData.certificatePem}>
                                        {({ copied, copy }) => (
                                            <Button size="compact-xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={13} />} onClick={copy}>
                                                {copied ? 'Copied' : 'Copy PEM'}
                                            </Button>
                                        )}
                                    </CopyButton>
                                    <Button size="compact-xs" variant="light" color="cyan" leftSection={<IconDownload size={13} />} onClick={() => downloadTextFile(certData.certificatePem, `${certModalSigner.code}.crt.pem`)}>
                                        Download
                                    </Button>
                                </Group>
                            </Group>
                            <Text size="xs" c="dimmed">Subject: <b>{certData.subjectDn}</b></Text>
                            <Text size="xs" c="dimmed">Issuer: <b>{certData.issuerDn}</b></Text>
                            <Code block mt="xs" style={{ maxHeight: 160, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                                {certData.certificatePem}
                            </Code>
                        </Paper>
                    ) : (
                        <Alert color="gray" variant="light">
                            No certificate imported yet (<Code>GET /api/v1/admin/signer/{certModalSigner?.id}/cert</Code> → 404). Import the CA-signed PEM below (verified against <Code>ocsp_keys</Code> in MariaDB with zero HSM token calls).
                        </Alert>
                    )}

                    {canOperate && (
                        <>
                            <Divider label={certData ? 'Import Replacement Certificate (POST /signer/{id}/cert)' : 'Import Certificate (POST /signer/{id}/cert)'} labelPosition="center" />
                            <form onSubmit={handleImportCert}>
                                <Stack gap="sm">
                                    <Group justify="space-between" align="flex-end">
                                        <Text size="sm" fw={500}>CA-Signed X.509 Certificate PEM</Text>
                                        <FileButton onChange={handleCertFileUpload} accept=".pem,.crt,.cer">
                                            {(props) => (
                                                <Button {...props} size="xs" variant="light" leftSection={<IconUpload size={14} />}>
                                                    Upload .pem / .crt
                                                </Button>
                                            )}
                                        </FileButton>
                                    </Group>
                                    <Textarea
                                        placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"
                                        minRows={5}
                                        maxRows={9}
                                        value={certPemInput}
                                        onChange={(e) => setCertPemInput(e.currentTarget.value)}
                                        required
                                    />
                                    {isAdmin && (
                                        <Switch
                                            label="Activate signer immediately after import"
                                            checked={certActivateNow}
                                            onChange={(e) => setCertActivateNow(e.currentTarget.checked)}
                                            color="green"
                                        />
                                    )}
                                    <Group justify="flex-end">
                                        <Button variant="default" onClick={() => setCertModalSigner(null)}>Close</Button>
                                        <Button type="submit" color="indigo" loading={certLoading} leftSection={<IconCertificate size={15} />}>
                                            Import Certificate into Signer
                                        </Button>
                                    </Group>
                                </Stack>
                            </form>
                        </>
                    )}
                </Stack>
            </Modal>

            {/* Modal: Quick Unlock HSM Token */}
            <Modal opened={Boolean(unlockDeviceId)} onClose={() => { setUnlockPin(''); setUnlockDeviceId(null); }} title={<Group gap="xs"><IconLockOpen size={20} color="#22c55e" /><Text fw={700}>Unlock HSM Token: {unlockDeviceId}</Text></Group>}>
                <form onSubmit={handleQuickUnlock}>
                    <Stack gap="md">
                        <Alert color="cyan" variant="light">
                            Enter the User PIN for <Code>{unlockDeviceId}</Code>. PIN is used once for <Code>C_Login</Code> and immediately wiped from memory.
                        </Alert>
                        <PasswordInput label="PKCS#11 User PIN" placeholder="Enter PIN" value={unlockPin} onChange={(e) => setUnlockPin(e.currentTarget.value)} autoFocus required />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => { setUnlockPin(''); setUnlockDeviceId(null); }}>Cancel</Button>
                            <Button type="submit" color="green" loading={saving} leftSection={<IconLockOpen size={16} />}>Unlock</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>
        </Container>
    );
};
