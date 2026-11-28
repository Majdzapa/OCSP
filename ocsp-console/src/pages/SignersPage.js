import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Container,
    Paper,
    Title,
    Text,
    Group,
    Stack,
    Button,
    Badge,
    Table,
    ActionIcon,
    Modal,
    TextInput,
    Textarea,
    PasswordInput,
    Select,
    MultiSelect,
    Switch,
    Alert,
    Loader,
    Tooltip,
    Code,
    Box,
    SimpleGrid,
    CopyButton,
    FileButton,
    Divider,
    Tabs,
    Card,
    ThemeIcon,
} from '@mantine/core';
import {
    IconKey,
    IconPlus,
    IconRefresh,
    IconCheck,
    IconTrash,
    IconEdit,
    IconAlertCircle,
    IconCopy,
    IconDownload,
    IconUpload,
    IconFileCertificate,
    IconCertificate,
    IconLock,
    IconLockOpen,
    IconCpu,
    IconX,
    IconEye,
    IconShieldCheck,
    IconPlayerPlay,
    IconPlayerPause,
    IconDatabaseImport,
    IconChevronDown,
    IconChevronRight,
    IconHierarchy2,
} from '@tabler/icons-react';
import {
    getSigners,
    getOcspKeys,
    createSigner,
    updateSigner,
    deleteSigner,
    generateSignerCsr,
    getSignerCsr,
    getSignerCertificate,
    importSignerCertificate,
    importSignerKeyCertificate,
    activateSignerKey,
    deleteSignerKey,
    activateSigner,
    deactivateSigner,
    getCryptoDevices,
    activateCryptoDevice,
    deactivateCryptoDevice,
    syncCryptoDeviceKeys,
    getProviderCapabilities,
    checkSigningAlgorithm,
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

function KeyStatusBadge({ status }) {
    if (status === 'ACTIVE') {
        return <Badge color="green" variant="filled" size="sm">ACTIVE</Badge>;
    }
    if (status === 'READY') {
        return <Badge color="teal" variant="light" size="sm">READY</Badge>;
    }
    if (status === 'CSR_PENDING') {
        return <Badge color="cyan" variant="outline" size="sm">CSR PENDING</Badge>;
    }
    if (status === 'INACTIVE') {
        return <Badge color="gray" variant="light" size="sm">STANDBY</Badge>;
    }
    if (status === 'EXPIRED') {
        return <Badge color="red" variant="filled" size="sm">EXPIRED</Badge>;
    }
    return <Badge color="orange" variant="outline" size="sm">UNAVAILABLE</Badge>;
}

function SignerStatusBadge({ status }) {
    if (status === 'ACTIVE') return <Badge color="green" variant="filled" size="sm">ACTIVE</Badge>;
    if (status === 'TOKEN_LOCKED') return <Badge color="orange" variant="filled" size="sm">TOKEN DEACTIVATED</Badge>;
    if (status === 'CERT_IMPORTED') return <Badge color="teal" variant="light" size="sm">CERT IMPORTED</Badge>;
    if (status === 'CSR_GENERATED') return <Badge color="cyan" variant="light" size="sm">CSR READY</Badge>;
    if (status === 'EXPIRED') return <Badge color="red" variant="filled" size="sm">EXPIRED</Badge>;
    return <Badge color="gray" variant="light" size="sm">{status || 'DRAFT'}</Badge>;
}

export const SignersPage = () => {
    const navigate = useNavigate();
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => (typeof r === 'string' ? r : r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');
    const canOperate = isAdmin || roleNames.includes('ROLE_AGENT');

    const [activeTab, setActiveTab] = useState('signers');
    const [signers, setSigners] = useState([]);
    const [keys, setKeys] = useState([]);
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [syncingDeviceId, setSyncingDeviceId] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    // Create / Edit Signer Modal
    const [formOpen, setFormOpen] = useState(false);
    const [editingId, setEditingId] = useState(null);
    const [code, setCode] = useState('');
    const [name, setName] = useState('');
    const [subjectDn, setSubjectDn] = useState('CN=Incert OCSP Signer,O=Incert,C=LU');
    const [useExistingKey, setUseExistingKey] = useState(false);
    const [selectedKeyId, setSelectedKeyId] = useState('');
    const [keyLabel, setKeyLabel] = useState('');
    const [keyAlgorithm, setKeyAlgorithm] = useState('RSA');
    const [keySize, setKeySize] = useState('3072');
    const [signatureAlgorithm, setSignatureAlgorithm] = useState('SHA256withRSA');
    const [tokenIds, setTokenIds] = useState([]);
    const [capabilities, setCapabilities] = useState(null);
    const [algCheck, setAlgCheck] = useState(null);

    // View Persisted Key Modal
    const [viewKeyModal, setViewKeyModal] = useState(null);

    // CSR Modal (includes target token selection when signer has multiple tokens)
    const [csrModalSigner, setCsrModalSigner] = useState(null);
    const [csrData, setCsrData] = useState(null);
    const [csrLoading, setCsrLoading] = useState(false);
    const [csrTargetTokenId, setCsrTargetTokenId] = useState('');
    const [csrAwaitingTokenChoice, setCsrAwaitingTokenChoice] = useState(false);

    // Certificate Modal (supports both signer-level and per-key zero-downtime rollover import)
    const [certModalSigner, setCertModalSigner] = useState(null);
    const [certModalKey, setCertModalKey] = useState(null);
    const [certData, setCertData] = useState(null);
    const [certPemInput, setCertPemInput] = useState('');
    const [certActivateNow, setCertActivateNow] = useState(true);
    const [certLoading, setCertLoading] = useState(false);

    // Expanded signer rows showing per-signer key list
    const [expandedSignerIds, setExpandedSignerIds] = useState({});
    const toggleSignerExpanded = (id) => {
        setExpandedSignerIds((prev) => ({ ...prev, [id]: !prev[id] }));
    };

    // Quick Unlock Modal
    const [unlockDeviceId, setUnlockDeviceId] = useState(null);
    const [unlockPin, setUnlockPin] = useState('');

    const fetchAll = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const [signerList, keyList, devList] = await Promise.all([
                getSigners(),
                getOcspKeys().catch(() => []),
                getCryptoDevices().catch(() => []),
            ]);
            setSigners(signerList || []);
            setKeys(keyList || []);
            setDevices(devList || []);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load OCSP Signers, Tokens & Keys');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAll();
    }, [fetchAll]);

    // Live capability check for primary token in Create/Edit modal
    useEffect(() => {
        if (!formOpen || tokenIds.length === 0) {
            setCapabilities(null);
            setAlgCheck(null);
            return;
        }
        const primary = tokenIds[0];
        let cancelled = false;
        getProviderCapabilities(primary)
            .then((caps) => { if (!cancelled) setCapabilities(caps); })
            .catch(() => { if (!cancelled) setCapabilities(null); });
        return () => { cancelled = true; };
    }, [formOpen, tokenIds]);

    useEffect(() => {
        if (!formOpen || tokenIds.length === 0 || !capabilities?.liveIntrospected) {
            setAlgCheck(null);
            return;
        }
        let cancelled = false;
        checkSigningAlgorithm({
            providerId: tokenIds[0],
            keyAlgorithm,
            keySize: Number(keySize),
            signatureAlgorithm,
        })
            .then((res) => { if (!cancelled) setAlgCheck(res); })
            .catch(() => { if (!cancelled) setAlgCheck(null); });
        return () => { cancelled = true; };
    }, [formOpen, tokenIds, capabilities, keyAlgorithm, keySize, signatureAlgorithm]);

    // Computed EJBCA metrics
    const stats = useMemo(() => {
        const activeTokens = devices.filter((d) => d.activationState === 'ACTIVE').length;
        const activeKeys = keys.filter((k) => k.status === 'ACTIVE').length;
        const standbyKeys = keys.filter((k) => k.status === 'INACTIVE').length;
        const unavailableKeys = keys.filter((k) => k.status === 'UNAVAILABLE' || k.status === 'EXPIRED').length;
        const activeSigners = signers.filter((s) => s.status === 'ACTIVE').length;
        const lockedSigners = signers.filter((s) => s.status === 'TOKEN_LOCKED').length;
        return {
            totalTokens: devices.length,
            activeTokens,
            totalKeys: keys.length,
            activeKeys,
            standbyKeys,
            unavailableKeys,
            totalSigners: signers.length,
            activeSigners,
            lockedSigners,
        };
    }, [devices, keys, signers]);

    // Group keys by token deviceId for EJBCA Crypto Token view
    const keysByTokenDeviceId = useMemo(() => {
        const map = new Map();
        for (const d of devices) {
            map.set(d.deviceId, []);
        }
        for (const k of keys) {
            const devCode = k.tokenDeviceCode || '__unassigned__';
            if (!map.has(devCode)) map.set(devCode, []);
            map.get(devCode).push(k);
        }
        return map;
    }, [devices, keys]);

    const openCreate = (presetTokenDeviceId = null, presetKey = null) => {
        setEditingId(null);
        setCode(generateUuid());
        setName('');
        setSubjectDn('CN=Incert OCSP Signer,O=Incert,C=LU');
        if (presetKey) {
            setUseExistingKey(true);
            setSelectedKeyId(String(presetKey.id));
            setKeyLabel(presetKey.keyLabel);
            setKeyAlgorithm(presetKey.keyAlgorithm || 'RSA');
            setKeySize(String(presetKey.keySize || 3072));
            setSignatureAlgorithm(presetKey.keyAlgorithm === 'EC' ? 'SHA256withECDSA' : 'SHA256withRSA');
        } else {
            setUseExistingKey(false);
            setSelectedKeyId('');
            setKeyLabel(generateUuid());
            setKeyAlgorithm('RSA');
            setKeySize('3072');
            setSignatureAlgorithm('SHA256withRSA');
        }
        if (presetTokenDeviceId) {
            setTokenIds([presetTokenDeviceId]);
        } else {
            const defaultDev = devices.find((d) => d.activationState === 'ACTIVE') || devices[0];
            setTokenIds(defaultDev ? [defaultDev.deviceId] : []);
        }
        setError(null);
        setFormOpen(true);
    };

    const openEdit = (s) => {
        setEditingId(s.id);
        setCode(s.code);
        setName(s.name);
        setSubjectDn(s.subjectDn);
        setUseExistingKey(Boolean(s.keyId));
        setSelectedKeyId(s.keyId ? String(s.keyId) : '');
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
                setSuccess(`Signer '${payload.name}' updated.`);
            } else {
                await createSigner(payload);
                setSuccess(`Signer '${payload.name}' created with ${tokenIds.length} HSM Token(s).`);
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
        if (!window.confirm(`Delete OCSP Signer '${s.name}' (${s.code})?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteSigner(s.id);
            setSuccess(`Signer '${s.name}' deleted.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete signer');
        } finally {
            setSaving(false);
        }
    };

    const executeCsrGeneration = async (s, chosenTokenDeviceId = null) => {
        try {
            setCsrLoading(true);
            setCsrAwaitingTokenChoice(false);
            setError(null);
            const reqBody = s.hasCsr ? { reuseExistingKey: false } : {};
            if (chosenTokenDeviceId) {
                reqBody.tokenDeviceId = chosenTokenDeviceId;
            }
            const generated = await generateSignerCsr(s.id, reqBody);
            setCsrData(generated);
            setSuccess(`Generated key '${generated.keyLabel}' & signed CSR on Token '${generated.tokenDeviceId}'.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to generate/load CSR');
        } finally {
            setCsrLoading(false);
        }
    };

    const openCsrModal = async (s, generateNow = false) => {
        setCsrModalSigner(s);
        setCsrData(null);
        setCsrAwaitingTokenChoice(false);
        setError(null);
        const boundTokens = s.tokens || [];
        if (generateNow || !s.hasCsr) {
            if (boundTokens.length > 1) {
                const firstActive = boundTokens.find((t) => t.activationState === 'ACTIVE') || boundTokens[0];
                setCsrTargetTokenId(firstActive?.deviceId || '');
                setCsrAwaitingTokenChoice(true);
                return;
            }
            await executeCsrGeneration(s, boundTokens[0]?.deviceId || null);
            return;
        }
        try {
            setCsrLoading(true);
            const existing = await getSignerCsr(s.id, false);
            setCsrData(existing);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load CSR');
        } finally {
            setCsrLoading(false);
        }
    };

    const openCertModal = async (s, targetKey = null) => {
        setCertModalSigner(s);
        setCertModalKey(targetKey);
        setCertData(null);
        setCertPemInput('');
        const hasActiveToken = (s.tokens || []).some((t) => t.activationState === 'ACTIVE');
        setCertActivateNow(isAdmin && hasActiveToken && !s.active);
        setError(null);
        if (targetKey) {
            if (targetKey.hasCertificate && targetKey.certificatePem) {
                setCertData({
                    serialNumber: targetKey.certSerialNumber,
                    issuerDn: targetKey.certIssuerDn,
                    subjectDn: s.subjectDn,
                    daysUntilExpiry: targetKey.certDaysUntilExpiry ?? 0,
                    expired: targetKey.status === 'EXPIRED',
                    signatureAlgorithm: s.signatureAlgorithm,
                    certificatePem: targetKey.certificatePem,
                });
            }
            return;
        }
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
            const payload = {
                certificatePem: certPemInput.trim(),
                signatureAlgorithm: certModalSigner.signatureAlgorithm,
                activateImmediately: isAdmin ? certActivateNow : false,
            };
            const updated = certModalKey
                ? await importSignerKeyCertificate(certModalSigner.id, certModalKey.id, payload)
                : await importSignerCertificate(certModalSigner.id, payload);
            setCertModalSigner(updated);
            if (certModalKey) {
                const updatedKey = (updated.keys || []).find((k) => k.id === certModalKey.id);
                setCertModalKey(updatedKey || null);
                setCertData(updatedKey?.certificatePem ? {
                    serialNumber: updatedKey.certSerialNumber,
                    issuerDn: updatedKey.certIssuerDn,
                    subjectDn: updated.subjectDn,
                    daysUntilExpiry: updatedKey.certDaysUntilExpiry ?? 0,
                    expired: updatedKey.status === 'EXPIRED',
                    signatureAlgorithm: updated.signatureAlgorithm,
                    certificatePem: updatedKey.certificatePem,
                } : null);
                setSuccess(`Imported X.509 certificate for Key #${certModalKey.id} ('${certModalKey.keyLabel}') under signer '${updated.name}'${payload.activateImmediately ? ' and activated' : ' (status: READY for 1-click cutover)'}.`);
            } else {
                setCertData(updated.certificate);
                setSuccess(`Imported X.509 certificate (serial ${updated.certificate?.serialNumber}) into signer '${updated.name}'.`);
            }
            setCertPemInput('');
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to import certificate into signer');
        } finally {
            setCertLoading(false);
        }
    };

    const handleActivateKey = async (signerId, keyId, keyAlias) => {
        try {
            setSaving(true);
            setError(null);
            await activateSignerKey(signerId, keyId);
            setSuccess(`Switched active key to '${keyAlias}' (Key #${keyId}). Previous active key was automatically deactivated.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to activate key');
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteKey = async (signerId, keyId, keyAlias) => {
        if (!window.confirm(`Delete inactive key '${keyAlias}' (Key #${keyId}) from this signer?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteSignerKey(signerId, keyId);
            setSuccess(`Deleted inactive key '${keyAlias}' (Key #${keyId}).`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete key');
        } finally {
            setSaving(false);
        }
    };

    const openKeyCsrModal = (signer, keyObj) => {
        setCsrModalSigner(signer);
        setCsrData({
            signerId: signer.id,
            signerCode: signer.code,
            tokenDeviceId: keyObj.tokenDeviceCode || signer.tokens?.[0]?.deviceId || 'HSM',
            keyId: keyObj.id,
            keyLabel: keyObj.keyLabel,
            keyAlgorithm: keyObj.keyAlgorithm,
            keySize: keyObj.keySize,
            publicKeySha1: keyObj.publicKeySha1,
            signatureAlgorithm: signer.signatureAlgorithm,
            subjectDn: signer.subjectDn,
            csrPem: keyObj.csrPem,
            generatedAt: keyObj.csrGeneratedAt,
        });
    };

    const handleCertFileUpload = (file) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            if (typeof reader.result === 'string') setCertPemInput(reader.result);
        };
        reader.readAsText(file);
    };

    const handleToggleSignerActive = async (signerId, currentlyActive, label) => {
        try {
            setSaving(true);
            setError(null);
            if (currentlyActive) {
                await deactivateSigner(signerId);
                setSuccess(`Signer '${label}' deactivated.`);
            } else {
                await activateSigner(signerId);
                setSuccess(`Signer '${label}' activated (any other active key in the same token was automatically deactivated).`);
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
            setSuccess(`Crypto Token '${unlockDeviceId}' activated (unlocked via C_Login). Keys in this token are now available.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to unlock Crypto Token');
        } finally {
            setSaving(false);
        }
    };

    const handleDeactivateToken = async (deviceId) => {
        if (!window.confirm(`Deactivate (lock) Crypto Token '${deviceId}'? All keys in this token will become UNAVAILABLE until unlocked with PIN.`)) {
            return;
        }
        try {
            setSaving(true);
            setError(null);
            await deactivateCryptoDevice(deviceId);
            setSuccess(`Crypto Token '${deviceId}' deactivated (LOCKED). All keys in this token are now UNAVAILABLE.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to deactivate Crypto Token');
        } finally {
            setSaving(false);
        }
    };

    const handleSyncTokenKeys = async (deviceId) => {
        try {
            setSyncingDeviceId(deviceId);
            setError(null);
            const synced = await syncCryptoDeviceKeys(deviceId);
            setSuccess(`Synchronized ${synced.length} key(s) from unlocked HSM Token '${deviceId}' into ocsp_keys.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to sync keys from HSM Token');
        } finally {
            setSyncingDeviceId(null);
        }
    };

    const tokenOptions = devices.map((d) => ({
        value: d.deviceId,
        label: `${d.deviceId} (${d.providerCode} · ${d.tokenLabel || 'slot ' + d.slotId} · ${d.activationState})`,
    }));

    const existingKeyOptions = keys.map((k) => ({
        value: String(k.id),
        label: `${k.keyLabel} (${k.keyAlgorithm} ${k.keySize} · ${k.tokenDeviceCode || 'HSM'} · ${k.status})`,
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

    return (
        <Container size="xl" py="md">
            <Stack gap="md">
                {/* Header */}
                <Group justify="space-between" align="flex-start" wrap="wrap">
                    <Box>
                        <Group gap="xs">
                            <ThemeIcon size={34} radius="md" variant="gradient" gradient={{ from: 'indigo', to: 'cyan' }}>
                                <IconKey size={20} />
                            </ThemeIcon>
                            <Box>
                                <Group gap="xs">
                                    <Title order={2} c="white" lh={1.1}>OCSP Signers &amp; Crypto Tokens</Title>
                                    <Badge color="indigo" variant="light" size="sm">EJBCA KEY BINDING MODEL</Badge>
                                </Group>
                                <Text c="dimmed" size="xs" mt={3}>
                                    Manage HSM Crypto Tokens, inspect every key&apos;s live status (max 1 active key per token), and bind OCSP Signers with zero idle HSM scans.
                                </Text>
                            </Box>
                        </Group>
                    </Box>
                    <Group gap="xs">
                        <Button variant="default" size="sm" leftSection={<IconRefresh size={15} />} onClick={fetchAll} loading={loading}>
                            Refresh
                        </Button>
                        {canOperate && (
                            <Button
                                variant="gradient"
                                gradient={{ from: 'indigo.6', to: 'violet.6' }}
                                size="sm"
                                leftSection={<IconPlus size={15} />}
                                onClick={() => openCreate()}
                            >
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

                {/* KPI Summary Row */}
                <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
                    <Card withBorder p="sm" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.55)' }}>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Crypto Tokens</Text>
                            <IconCpu size={16} color="#38bdf8" />
                        </Group>
                        <Group gap="xs" align="baseline" mt={4}>
                            <Text fz={24} fw={700} c={stats.activeTokens > 0 ? 'teal.4' : 'orange.4'}>
                                {stats.activeTokens} / {stats.totalTokens}
                            </Text>
                            <Text size="xs" c="dimmed">active (unlocked)</Text>
                        </Group>
                    </Card>

                    <Card withBorder p="sm" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.55)' }}>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Token Keys (ocsp_keys)</Text>
                            <IconKey size={16} color="#818cf8" />
                        </Group>
                        <Group gap={6} mt={6} wrap="wrap">
                            <Badge color="green" variant="filled" size="sm">{stats.activeKeys} Active</Badge>
                            <Badge color="cyan" variant="light" size="sm">{stats.standbyKeys} Standby</Badge>
                            <Badge color="orange" variant="outline" size="sm">{stats.unavailableKeys} Unavailable</Badge>
                        </Group>
                    </Card>

                    <Card withBorder p="sm" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.55)' }}>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>OCSP Signers (Key Bindings)</Text>
                            <IconShieldCheck size={16} color="#22c55e" />
                        </Group>
                        <Group gap="xs" align="baseline" mt={4}>
                            <Text fz={24} fw={700} c="white">
                                {stats.activeSigners} / {stats.totalSigners}
                            </Text>
                            <Text size="xs" c="dimmed">
                                active{stats.lockedSigners > 0 ? ` · ${stats.lockedSigners} token locked` : ''}
                            </Text>
                        </Group>
                    </Card>
                </SimpleGrid>

                {/* Live Crypto Tokens Quick Bar (always visible) */}
                {devices.length > 0 && (
                    <Paper withBorder p="sm" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.45)' }}>
                        <Group justify="space-between" mb="xs">
                            <Group gap="xs">
                                <IconCpu size={16} color="#38bdf8" />
                                <Text size="xs" fw={700} tt="uppercase" c="dimmed">
                                    HSM Crypto Tokens ({devices.length}) — Deactivating a token disables all keys inside it
                                </Text>
                            </Group>
                            <Button size="compact-xs" variant="subtle" color="cyan" onClick={() => setActiveTab('tokens')}>
                                Inspect All Tokens &amp; Keys →
                            </Button>
                        </Group>
                        <Group gap="xs" wrap="wrap">
                            {devices.map((d) => {
                                const isActive = d.activationState === 'ACTIVE';
                                const tokenKeys = keysByTokenDeviceId.get(d.deviceId) || [];
                                const activeCount = tokenKeys.filter((k) => k.status === 'ACTIVE').length;
                                return (
                                    <Paper
                                        key={d.deviceId}
                                        withBorder
                                        px="sm"
                                        py={6}
                                        radius="sm"
                                        style={{
                                            backgroundColor: isActive ? 'rgba(34, 197, 94, 0.08)' : 'rgba(249, 115, 22, 0.08)',
                                            borderColor: isActive ? 'rgba(34, 197, 94, 0.35)' : 'rgba(249, 115, 22, 0.35)',
                                        }}
                                    >
                                        <Group gap="xs" wrap="nowrap">
                                            <Badge size="xs" color={isActive ? 'green' : 'orange'} variant="dot">
                                                {isActive ? 'ACTIVE' : 'DEACTIVATED'}
                                            </Badge>
                                            <Text size="xs" fw={700} c="white">{d.deviceId}</Text>
                                            <Text size="xs" c="dimmed">
                                                ({tokenKeys.length} key{tokenKeys.length === 1 ? '' : 's'}{isActive ? `, ${activeCount} active` : ' · disabled'})
                                            </Text>
                                            {isAdmin && (
                                                isActive ? (
                                                    <Tooltip label="Deactivate (Lock) token — disables all keys in this token">
                                                        <ActionIcon
                                                            size="xs"
                                                            variant="subtle"
                                                            color="orange"
                                                            onClick={() => handleDeactivateToken(d.deviceId)}
                                                        >
                                                            <IconLock size={13} />
                                                        </ActionIcon>
                                                    </Tooltip>
                                                ) : (
                                                    <Button
                                                        size="compact-xs"
                                                        variant="light"
                                                        color="green"
                                                        leftSection={<IconLockOpen size={12} />}
                                                        onClick={() => { setUnlockPin(''); setUnlockDeviceId(d.deviceId); }}
                                                    >
                                                        Activate
                                                    </Button>
                                                )
                                            )}
                                        </Group>
                                    </Paper>
                                );
                            })}
                        </Group>
                    </Paper>
                )}

                {/* Main EJBCA-Style Tabs */}
                <Tabs value={activeTab} onChange={setActiveTab} color="indigo" variant="outline">
                    <Tabs.List>
                        <Tabs.Tab value="signers" leftSection={<IconShieldCheck size={16} />}>
                            OCSP Signers (Key Bindings) ({signers.length})
                        </Tabs.Tab>
                        <Tabs.Tab value="tokens" leftSection={<IconCpu size={16} />}>
                            Crypto Tokens &amp; Available Keys ({devices.length} tokens · {keys.length} keys)
                        </Tabs.Tab>
                    </Tabs.List>

                    {/* ============================================================= */}
                    {/* TAB 1: OCSP SIGNERS (EJBCA INTERNAL KEY BINDINGS TABLE)       */}
                    {/* ============================================================= */}
                    <Tabs.Panel value="signers" pt="md">
                        {loading ? (
                            <Group justify="center" p="xl"><Loader size="md" /></Group>
                        ) : signers.length === 0 ? (
                            <Paper withBorder p="xl" radius="md" ta="center">
                                <Text c="dimmed" mb="md">No OCSP Signers configured yet.</Text>
                                {canOperate && (
                                    <Button variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} leftSection={<IconPlus size={15} />} onClick={() => openCreate()}>
                                        Create First OCSP Signer
                                    </Button>
                                )}
                            </Paper>
                        ) : (
                            <Paper withBorder radius="md" p="xs" style={{ backgroundColor: 'rgba(15, 23, 42, 0.5)' }}>
                                <Table.ScrollContainer minWidth={960}>
                                    <Table verticalSpacing="sm" highlightOnHover>
                                        <Table.Thead>
                                            <Table.Tr>
                                                <Table.Th>Status</Table.Th>
                                                <Table.Th>Signer (Key Binding)</Table.Th>
                                                <Table.Th>Crypto Token(s)</Table.Th>
                                                <Table.Th>Key &amp; Key Status</Table.Th>
                                                <Table.Th>X.509 Certificate</Table.Th>
                                                <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                            </Table.Tr>
                                        </Table.Thead>
                                        <Table.Tbody>
                                            {signers.map((s) => {
                                                const anyTokenActive = (s.tokens || []).some((t) => t.activationState === 'ACTIVE');
                                                const signerKeys = s.keys || (s.key ? [s.key] : []);
                                                const isExpanded = Boolean(expandedSignerIds[s.id]);
                                                const keyStatus = s.key?.status || (anyTokenActive ? 'INACTIVE' : 'UNAVAILABLE');
                                                return (
                                                    <React.Fragment key={s.id}>
                                                        <Table.Tr
                                                            style={s.status === 'ACTIVE'
                                                                ? { backgroundColor: 'rgba(34, 197, 94, 0.06)' }
                                                                : s.status === 'TOKEN_LOCKED'
                                                                    ? { backgroundColor: 'rgba(249, 115, 22, 0.06)' }
                                                                    : undefined}
                                                        >
                                                            <Table.Td>
                                                                <Stack gap={4}>
                                                                    <SignerStatusBadge status={s.status} />
                                                                    <Text size="10px" c="dimmed">ID #{s.id}</Text>
                                                                </Stack>
                                                            </Table.Td>

                                                            <Table.Td>
                                                                <Text
                                                                    fw={700}
                                                                    size="sm"
                                                                    c="indigo.3"
                                                                    style={{ cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 3 }}
                                                                    onClick={() => navigate(`/signers/${s.id}`)}
                                                                >
                                                                    {s.name}
                                                                </Text>
                                                                <Text size="xs" c="dimmed" lineClamp={1}>{s.subjectDn}</Text>
                                                                <Code fz={10}>{s.code}</Code>
                                                            </Table.Td>

                                                            <Table.Td>
                                                                <Stack gap={4}>
                                                                    {(s.tokens || []).map((t) => {
                                                                        const isUp = t.activationState === 'ACTIVE';
                                                                        return (
                                                                            <Group key={t.deviceId} gap={5} wrap="nowrap">
                                                                                <Badge size="xs" color={t.role === 'PRIMARY' ? 'blue' : 'gray'} variant="filled">
                                                                                    {t.role === 'PRIMARY' ? '1°' : 'HA'}
                                                                                </Badge>
                                                                                <Code fz={11}>{t.deviceId}</Code>
                                                                                <Badge size="xs" color={isUp ? 'green' : 'orange'} variant="dot">
                                                                                    {isUp ? 'ACTIVE' : 'LOCKED'}
                                                                                </Badge>
                                                                            </Group>
                                                                        );
                                                                    })}
                                                                </Stack>
                                                            </Table.Td>

                                                            <Table.Td>
                                                                <Stack gap={4}>
                                                                    <Group gap={5} wrap="nowrap">
                                                                        <KeyStatusBadge status={s.key ? keyStatus : 'UNAVAILABLE'} />
                                                                        <Badge size="xs" color="cyan" variant="light">
                                                                            {s.keyAlgorithm} {s.keySize}
                                                                        </Badge>
                                                                        <Button
                                                                            size="compact-xs"
                                                                            variant={isExpanded ? 'filled' : 'light'}
                                                                            color="indigo"
                                                                            leftSection={isExpanded ? <IconChevronDown size={12} /> : <IconChevronRight size={12} />}
                                                                            onClick={() => toggleSignerExpanded(s.id)}
                                                                        >
                                                                            Keys ({signerKeys.length})
                                                                        </Button>
                                                                    </Group>
                                                                    <Text size="11px" c="dimmed" ff="monospace" lineClamp={1} title={s.keyLabel}>
                                                                        {s.keyLabel}
                                                                    </Text>
                                                                    <Text size="10px" c="dimmed">{s.signatureAlgorithm}</Text>
                                                                </Stack>
                                                            </Table.Td>

                                                            <Table.Td>
                                                                {s.certificate ? (
                                                                    <Stack gap={2}>
                                                                        <Group gap={5}>
                                                                            <Badge size="xs" color={s.certificate.expired ? 'red' : 'teal'} variant="light">
                                                                                {s.certificate.expired ? 'EXPIRED' : `${s.certificate.daysUntilExpiry}d left`}
                                                                            </Badge>
                                                                            <Code fz={10}>{s.certificate.serialNumber}</Code>
                                                                        </Group>
                                                                        <Text size="11px" c="dimmed" lineClamp={1} title={s.certificate.issuerDn}>
                                                                            Issuer: {s.certificate.issuerDn}
                                                                        </Text>
                                                                    </Stack>
                                                                ) : s.hasCsr ? (
                                                                    <Badge color="cyan" variant="outline" size="xs">Awaiting CA-Signed Cert</Badge>
                                                                ) : (
                                                                    <Text size="xs" c="dimmed">No CSR / Cert yet</Text>
                                                                )}
                                                            </Table.Td>

                                                            <Table.Td style={{ textAlign: 'right' }}>
                                                                <Group justify="flex-end" gap={6} wrap="nowrap">
                                                                    <Tooltip label="Open Signer Architecture Graph & Detail View">
                                                                        <Button
                                                                            size="compact-xs"
                                                                            variant="light"
                                                                            color="violet"
                                                                            leftSection={<IconHierarchy2 size={13} />}
                                                                            onClick={() => navigate(`/signers/${s.id}`)}
                                                                        >
                                                                            Graph
                                                                        </Button>
                                                                    </Tooltip>
                                                                    <Tooltip label={s.active ? 'Generate Next Key & CSR (zero-downtime rollover)' : (s.hasCsr ? 'View or Re-generate Key & CSR' : 'Step 1: Generate Key & CSR')}>
                                                                        <Button
                                                                            size="compact-xs"
                                                                            variant={s.hasCsr ? 'light' : 'filled'}
                                                                            color="cyan"
                                                                            leftSection={<IconFileCertificate size={13} />}
                                                                            disabled={!anyTokenActive && !s.hasCsr}
                                                                            onClick={() => openCsrModal(s, s.active || !s.hasCsr)}
                                                                        >
                                                                            {s.active ? '+ Next Key' : 'CSR'}
                                                                        </Button>
                                                                    </Tooltip>
                                                                    <Tooltip label={s.hasCertificate ? 'View or Replace Certificate' : 'Step 2: Import CA-Signed Certificate'}>
                                                                        <Button
                                                                            size="compact-xs"
                                                                            variant={s.hasCertificate ? 'light' : 'filled'}
                                                                            color="indigo"
                                                                            leftSection={<IconCertificate size={13} />}
                                                                            onClick={() => openCertModal(s)}
                                                                        >
                                                                            Cert
                                                                        </Button>
                                                                    </Tooltip>
                                                                    {isAdmin && s.hasCertificate && (
                                                                        <Tooltip
                                                                            label={!s.active && !anyTokenActive
                                                                                ? 'Unlock a bound Crypto Token first to activate this signer'
                                                                                : s.active
                                                                                    ? 'Deactivate signer'
                                                                                    : 'Activate signer (deactivates any other active key in the same token)'}
                                                                        >
                                                                            <Button
                                                                                size="compact-xs"
                                                                                variant={s.active ? 'light' : 'filled'}
                                                                                color={s.active ? 'orange' : 'green'}
                                                                                leftSection={s.active ? <IconPlayerPause size={13} /> : <IconPlayerPlay size={13} />}
                                                                                loading={saving}
                                                                                disabled={!s.active && !anyTokenActive}
                                                                                onClick={() => handleToggleSignerActive(s.id, s.active, s.name)}
                                                                            >
                                                                                {s.active ? 'Deactivate' : 'Activate'}
                                                                            </Button>
                                                                        </Tooltip>
                                                                    )}
                                                                    {canOperate && (
                                                                        <Tooltip label="Edit Signer, Key & Tokens">
                                                                            <ActionIcon variant="light" color="blue" size="sm" onClick={() => openEdit(s)}>
                                                                                <IconEdit size={14} />
                                                                            </ActionIcon>
                                                                        </Tooltip>
                                                                    )}
                                                                    {isAdmin && !s.active && (
                                                                        <Tooltip label="Delete Signer">
                                                                            <ActionIcon variant="light" color="red" size="sm" onClick={() => handleDeleteSigner(s)}>
                                                                                <IconTrash size={14} />
                                                                            </ActionIcon>
                                                                        </Tooltip>
                                                                    )}
                                                                </Group>
                                                            </Table.Td>
                                                        </Table.Tr>

                                                        {/* Expandable EJBCA Per-Signer Keys Panel (max 1 ACTIVE key per Signer) */}
                                                        {isExpanded && (
                                                            <Table.Tr style={{ backgroundColor: 'rgba(15, 23, 42, 0.78)' }}>
                                                                <Table.Td colSpan={6} p="sm">
                                                                    <Paper withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.28)' }}>
                                                                        <Group justify="space-between" mb="xs">
                                                                            <Group gap="xs">
                                                                                <IconKey size={15} color="#818cf8" />
                                                                                <Text size="xs" fw={700} tt="uppercase" c="indigo.3">
                                                                                    Keys Owned by Signer &apos;{s.name}&apos; ({signerKeys.length}) — Only 1 Key Active at a Time
                                                                                </Text>
                                                                            </Group>
                                                                            {canOperate && (
                                                                                <Button
                                                                                    size="compact-xs"
                                                                                    variant="light"
                                                                                    color="cyan"
                                                                                    leftSection={<IconPlus size={12} />}
                                                                                    disabled={!anyTokenActive}
                                                                                    onClick={() => openCsrModal(s, true)}
                                                                                >
                                                                                    Generate Next Key &amp; CSR
                                                                                </Button>
                                                                            )}
                                                                        </Group>

                                                                        {signerKeys.length === 0 ? (
                                                                            <Text size="xs" c="dimmed">
                                                                                No keys generated for this signer yet. Click <b>Generate Next Key &amp; CSR</b> to create the first keypair on an active HSM Token.
                                                                            </Text>
                                                                        ) : (
                                                                            <Table verticalSpacing={6} fz="xs">
                                                                                <Table.Thead>
                                                                                    <Table.Tr>
                                                                                        <Table.Th>Key Status</Table.Th>
                                                                                        <Table.Th>Key Alias</Table.Th>
                                                                                        <Table.Th>Token</Table.Th>
                                                                                        <Table.Th>Algorithm</Table.Th>
                                                                                        <Table.Th>Certificate</Table.Th>
                                                                                        <Table.Th style={{ textAlign: 'right' }}>Key Actions</Table.Th>
                                                                                    </Table.Tr>
                                                                                </Table.Thead>
                                                                                <Table.Tbody>
                                                                                    {signerKeys.map((k) => {
                                                                                        const isKeyActive = k.status === 'ACTIVE' || k.active;
                                                                                        const disabledByToken = !k.tokenActive;
                                                                                        return (
                                                                                            <Table.Tr
                                                                                                key={k.id}
                                                                                                style={{
                                                                                                    opacity: disabledByToken ? 0.6 : 1,
                                                                                                    backgroundColor: isKeyActive ? 'rgba(34, 197, 94, 0.08)' : undefined,
                                                                                                }}
                                                                                            >
                                                                                                <Table.Td><KeyStatusBadge status={k.status} /></Table.Td>
                                                                                                <Table.Td>
                                                                                                    <Code fz={11}>{k.keyLabel}</Code>
                                                                                                    <Text span size="10px" c="dimmed" ml={6}>#{k.id}</Text>
                                                                                                </Table.Td>
                                                                                                <Table.Td>
                                                                                                    <Group gap={4} wrap="nowrap">
                                                                                                        <Code fz={10}>{k.tokenDeviceCode || 'HSM'}</Code>
                                                                                                        <Badge size="xs" color={k.tokenActive ? 'green' : 'orange'} variant="dot">
                                                                                                            {k.tokenState}
                                                                                                        </Badge>
                                                                                                    </Group>
                                                                                                </Table.Td>
                                                                                                <Table.Td>
                                                                                                    <Badge size="xs" color="cyan" variant="light">{k.keyAlgorithm} {k.keySize}</Badge>
                                                                                                </Table.Td>
                                                                                                <Table.Td>
                                                                                                    {k.hasCertificate ? (
                                                                                                        <Group gap={4}>
                                                                                                            <Badge size="xs" color={k.certDaysUntilExpiry != null && k.certDaysUntilExpiry < 0 ? 'red' : 'teal'} variant="light">
                                                                                                                {k.certDaysUntilExpiry != null && k.certDaysUntilExpiry < 0 ? 'Expired' : `${k.certDaysUntilExpiry}d left`}
                                                                                                            </Badge>
                                                                                                            {k.certSerialNumber && <Code fz={10}>{k.certSerialNumber}</Code>}
                                                                                                        </Group>
                                                                                                    ) : k.hasCsr ? (
                                                                                                        <Text size="xs" c="cyan.3">CSR ready · awaiting cert</Text>
                                                                                                    ) : (
                                                                                                        <Text size="xs" c="dimmed">No cert</Text>
                                                                                                    )}
                                                                                                </Table.Td>
                                                                                                <Table.Td style={{ textAlign: 'right' }}>
                                                                                                    <Group justify="flex-end" gap={4} wrap="nowrap">
                                                                                                        <Tooltip label="Inspect Public Key">
                                                                                                            <ActionIcon size="xs" variant="subtle" color="cyan" onClick={() => setViewKeyModal(k)}>
                                                                                                                <IconEye size={13} />
                                                                                                            </ActionIcon>
                                                                                                        </Tooltip>
                                                                                                        {k.hasCsr && (
                                                                                                            <Button size="compact-xs" variant="subtle" color="cyan" onClick={() => openKeyCsrModal(s, k)}>
                                                                                                                CSR
                                                                                                            </Button>
                                                                                                        )}
                                                                                                        {canOperate && (
                                                                                                            <Button size="compact-xs" variant="light" color="indigo" onClick={() => openCertModal(s, k)}>
                                                                                                                {k.hasCertificate ? 'Cert' : 'Import Cert'}
                                                                                                            </Button>
                                                                                                        )}
                                                                                                        {isAdmin && k.hasCertificate && !isKeyActive && (
                                                                                                            <Tooltip label={disabledByToken ? 'Token is deactivated — activate token first' : 'Switch active key to this key (zero-downtime rollover)'}>
                                                                                                                <Button
                                                                                                                    size="compact-xs"
                                                                                                                    variant="filled"
                                                                                                                    color="green"
                                                                                                                    disabled={disabledByToken}
                                                                                                                    loading={saving}
                                                                                                                    onClick={() => handleActivateKey(s.id, k.id, k.keyLabel)}
                                                                                                                >
                                                                                                                    Set Active
                                                                                                                </Button>
                                                                                                            </Tooltip>
                                                                                                        )}
                                                                                                        {isAdmin && !isKeyActive && (
                                                                                                            <Tooltip label="Delete inactive key">
                                                                                                                <ActionIcon size="xs" variant="subtle" color="red" onClick={() => handleDeleteKey(s.id, k.id, k.keyLabel)}>
                                                                                                                    <IconTrash size={13} />
                                                                                                                </ActionIcon>
                                                                                                            </Tooltip>
                                                                                                        )}
                                                                                                    </Group>
                                                                                                </Table.Td>
                                                                                            </Table.Tr>
                                                                                        );
                                                                                    })}
                                                                                </Table.Tbody>
                                                                            </Table>
                                                                        )}
                                                                    </Paper>
                                                                </Table.Td>
                                                            </Table.Tr>
                                                        )}
                                                    </React.Fragment>
                                                );
                                            })}
                                        </Table.Tbody>
                                    </Table>
                                </Table.ScrollContainer>
                            </Paper>
                        )}
                    </Tabs.Panel>

                    {/* ============================================================= */}
                    {/* TAB 2: EJBCA CRYPTO TOKENS & AVAILABLE KEYS VIEW              */}
                    {/* ============================================================= */}
                    <Tabs.Panel value="tokens" pt="md">
                        {loading ? (
                            <Group justify="center" p="xl"><Loader size="md" /></Group>
                        ) : devices.length === 0 ? (
                            <Paper withBorder p="xl" radius="md" ta="center">
                                <Text c="dimmed">No HSM Crypto Tokens configured yet. Configure them under HSM Devices &amp; Slots.</Text>
                            </Paper>
                        ) : (
                            <Stack gap="md">
                                {devices.map((d) => {
                                    const tokenActive = d.activationState === 'ACTIVE';
                                    const tokenKeys = keysByTokenDeviceId.get(d.deviceId) || [];
                                    const activeKey = tokenKeys.find((k) => k.status === 'ACTIVE');

                                    return (
                                        <Paper
                                            key={d.deviceId}
                                            withBorder
                                            p="md"
                                            radius="md"
                                            style={{
                                                backgroundColor: 'rgba(15, 23, 42, 0.55)',
                                                borderColor: tokenActive ? 'rgba(34, 197, 94, 0.4)' : 'rgba(249, 115, 22, 0.35)',
                                            }}
                                        >
                                            <Stack gap="sm">
                                                {/* Token Header */}
                                                <Group justify="space-between" wrap="wrap" gap="xs">
                                                    <Group gap="xs">
                                                        <Badge size="md" color={tokenActive ? 'green' : 'orange'} variant="filled">
                                                            {tokenActive ? 'TOKEN ACTIVE' : 'TOKEN DEACTIVATED'}
                                                        </Badge>
                                                        <Text fw={700} fz="md" c="white">{d.deviceId}</Text>
                                                        <Badge size="xs" color="blue" variant="light">{d.providerCode}</Badge>
                                                        <Text size="xs" c="dimmed">
                                                            Token: <Code>{d.tokenLabel || 'n/a'}</Code>
                                                            {d.slotId != null ? <> · Slot <Code>{d.slotId}</Code></> : null}
                                                        </Text>
                                                        <Badge size="xs" color="indigo" variant="outline">
                                                            {tokenKeys.length} key{tokenKeys.length === 1 ? '' : 's'}
                                                            {activeKey ? ' · 1 active (max 1)' : ' · 0 active'}
                                                        </Badge>
                                                    </Group>

                                                    <Group gap="xs">
                                                        {isAdmin && tokenActive && (
                                                            <>
                                                                <Tooltip label="Explicitly scan this unlocked HSM token for pre-existing keys and save them into ocsp_keys">
                                                                    <Button
                                                                        size="compact-xs"
                                                                        variant="light"
                                                                        color="cyan"
                                                                        leftSection={<IconDatabaseImport size={13} />}
                                                                        loading={syncingDeviceId === d.deviceId}
                                                                        onClick={() => handleSyncTokenKeys(d.deviceId)}
                                                                    >
                                                                        Sync Keys from HSM
                                                                    </Button>
                                                                </Tooltip>
                                                                <Button
                                                                    size="compact-xs"
                                                                    variant="light"
                                                                    color="orange"
                                                                    leftSection={<IconLock size={13} />}
                                                                    loading={saving}
                                                                    onClick={() => handleDeactivateToken(d.deviceId)}
                                                                >
                                                                    Deactivate Token
                                                                </Button>
                                                            </>
                                                        )}
                                                        {isAdmin && !tokenActive && (
                                                            <Button
                                                                size="compact-xs"
                                                                variant="filled"
                                                                color="green"
                                                                leftSection={<IconLockOpen size={13} />}
                                                                onClick={() => { setUnlockPin(''); setUnlockDeviceId(d.deviceId); }}
                                                            >
                                                                Activate Token (PIN)
                                                            </Button>
                                                        )}
                                                    </Group>
                                                </Group>

                                                {!tokenActive && (
                                                    <Alert color="orange" variant="light" py={6} icon={<IconLock size={16} />}>
                                                        Crypto Token <Code>{d.deviceId}</Code> is deactivated (LOCKED) — all {tokenKeys.length} key(s) in this token are <b>UNAVAILABLE (disabled)</b> until activated with the HSM PIN.
                                                    </Alert>
                                                )}

                                                {/* Keys Table inside this Token */}
                                                {tokenKeys.length === 0 ? (
                                                    <Paper withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                                                        <Group justify="space-between">
                                                            <Text size="xs" c="dimmed">
                                                                No keys registered in <Code>ocsp_keys</Code> for this token yet. Generate a CSR on a Signer or click <b>Sync Keys from HSM</b> when unlocked.
                                                            </Text>
                                                            {canOperate && (
                                                                <Button size="compact-xs" variant="subtle" color="indigo" onClick={() => openCreate(d.deviceId, null)}>
                                                                    + New Signer on Token
                                                                </Button>
                                                            )}
                                                        </Group>
                                                    </Paper>
                                                ) : (
                                                    <Table.ScrollContainer minWidth={780}>
                                                        <Table verticalSpacing="xs" highlightOnHover>
                                                            <Table.Thead>
                                                                <Table.Tr>
                                                                    <Table.Th>Key Status</Table.Th>
                                                                    <Table.Th>Key Alias / Label</Table.Th>
                                                                    <Table.Th>Algorithm</Table.Th>
                                                                    <Table.Th>Public Key SHA-1 (SKI)</Table.Th>
                                                                    <Table.Th>Bound OCSP Signer</Table.Th>
                                                                    <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                                                </Table.Tr>
                                                            </Table.Thead>
                                                            <Table.Tbody>
                                                                {tokenKeys.map((k) => {
                                                                    const isKeyActive = k.status === 'ACTIVE';
                                                                    const isDisabled = !k.tokenActive;
                                                                    return (
                                                                        <Table.Tr
                                                                            key={k.id}
                                                                            style={{
                                                                                opacity: isDisabled ? 0.6 : 1,
                                                                                backgroundColor: isKeyActive ? 'rgba(34, 197, 94, 0.08)' : undefined,
                                                                            }}
                                                                        >
                                                                            <Table.Td>
                                                                                <KeyStatusBadge status={k.status} />
                                                                            </Table.Td>
                                                                            <Table.Td>
                                                                                <Group gap={6} wrap="nowrap">
                                                                                    <Code fz={11}>{k.keyLabel}</Code>
                                                                                    <Text size="10px" c="dimmed">#{k.id}</Text>
                                                                                </Group>
                                                                            </Table.Td>
                                                                            <Table.Td>
                                                                                <Badge size="xs" color="cyan" variant="light">
                                                                                    {k.keyAlgorithm} {k.keySize}
                                                                                </Badge>
                                                                            </Table.Td>
                                                                            <Table.Td>
                                                                                <Code fz={10}>{k.publicKeySha1}</Code>
                                                                            </Table.Td>
                                                                            <Table.Td>
                                                                                {k.boundSignerId ? (
                                                                                    <Group gap={6}>
                                                                                        <Text size="xs" fw={600} c="white">{k.boundSignerName}</Text>
                                                                                        {k.hasCertificate ? (
                                                                                            <Badge size="xs" color={k.certDaysUntilExpiry != null && k.certDaysUntilExpiry < 0 ? 'red' : 'teal'} variant="light">
                                                                                                {k.certDaysUntilExpiry != null && k.certDaysUntilExpiry < 0 ? 'Expired' : `${k.certDaysUntilExpiry}d left`}
                                                                                            </Badge>
                                                                                        ) : (
                                                                                            <Badge size="xs" color="gray" variant="outline">No cert</Badge>
                                                                                        )}
                                                                                    </Group>
                                                                                ) : (
                                                                                    <Text size="xs" c="dimmed">Unbound</Text>
                                                                                )}
                                                                            </Table.Td>
                                                                            <Table.Td style={{ textAlign: 'right' }}>
                                                                                <Group justify="flex-end" gap={6} wrap="nowrap">
                                                                                    <Tooltip label="View persisted Public Key SPKI (0 HSM calls)">
                                                                                        <ActionIcon size="sm" variant="light" color="cyan" onClick={() => setViewKeyModal(k)}>
                                                                                            <IconEye size={14} />
                                                                                        </ActionIcon>
                                                                                    </Tooltip>
                                                                                    {isAdmin && k.boundSignerId && k.hasCertificate && (
                                                                                        <Tooltip
                                                                                            label={isDisabled
                                                                                                ? 'Token is deactivated — unlock token first'
                                                                                                : isKeyActive
                                                                                                    ? 'Deactivate this key / signer'
                                                                                                    : 'Set as the single active key in this token'}
                                                                                        >
                                                                                            <Button
                                                                                                size="compact-xs"
                                                                                                variant={isKeyActive ? 'light' : 'filled'}
                                                                                                color={isKeyActive ? 'orange' : 'green'}
                                                                                                disabled={isDisabled}
                                                                                                loading={saving}
                                                                                                 onClick={() => (isKeyActive
                                                                                                    ? handleToggleSignerActive(k.boundSignerId, true, k.boundSignerName)
                                                                                                    : handleActivateKey(k.boundSignerId, k.id, k.keyLabel))}
                                                                                            >
                                                                                                {isKeyActive ? 'Deactivate' : 'Set Active'}
                                                                                            </Button>
                                                                                        </Tooltip>
                                                                                    )}
                                                                                    {canOperate && !k.boundSignerId && (
                                                                                        <Button
                                                                                            size="compact-xs"
                                                                                            variant="light"
                                                                                            color="indigo"
                                                                                            onClick={() => openCreate(d.deviceId, k)}
                                                                                        >
                                                                                            Bind to Signer
                                                                                        </Button>
                                                                                    )}
                                                                                </Group>
                                                                            </Table.Td>
                                                                        </Table.Tr>
                                                                    );
                                                                })}
                                                            </Table.Tbody>
                                                        </Table>
                                                    </Table.ScrollContainer>
                                                )}
                                            </Stack>
                                        </Paper>
                                    );
                                })}
                            </Stack>
                        )}
                    </Tabs.Panel>
                </Tabs>
            </Stack>

            {/* Modal: Create / Edit Signer */}
            <Modal
                opened={formOpen}
                onClose={() => setFormOpen(false)}
                title={<Group gap="xs"><IconKey size={20} color="#818cf8" /><Text fw={700}>{editingId != null ? 'Edit OCSP Signer' : 'New OCSP Signer (Key Binding)'}</Text></Group>}
                size="lg"
            >
                <form onSubmit={handleSaveSigner}>
                    <Stack gap="md">
                        <SimpleGrid cols={2}>
                            <TextInput
                                label="Signer Code (UUID)"
                                description="Auto-generated unique identifier"
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
                            <TextInput label="Display Name" placeholder="Incert Intermediate CA OCSP Signer" value={name} onChange={(e) => setName(e.currentTarget.value)} required />
                        </SimpleGrid>

                        <MultiSelect
                            label="Bound Crypto Token(s) (1st = PRIMARY, others = FAILOVER)"
                            description="Attach one or more HSM Tokens. Only one key/signer can be active per token."
                            placeholder="Select Crypto Token(s)"
                            data={tokenOptions}
                            value={tokenIds}
                            onChange={setTokenIds}
                            searchable
                            required
                        />

                        {keys.length > 0 && (
                            <Switch
                                label="Bind an existing key from ocsp_keys"
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
                                    description="Loaded from MariaDB (zero HSM calls)"
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
                                    description="Generated on token & persisted to ocsp_keys on CSR creation"
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

            {/* Modal: View Persisted Public Key */}
            <Modal
                opened={Boolean(viewKeyModal)}
                onClose={() => setViewKeyModal(null)}
                title={<Group gap="xs"><IconKey size={20} color="#2dd4bf" /><Text fw={700}>Key #{viewKeyModal?.id}: {viewKeyModal?.keyLabel}</Text></Group>}
                size="lg"
            >
                {viewKeyModal && (
                    <Stack gap="sm">
                        <Group gap="xs">
                            <KeyStatusBadge status={viewKeyModal.status} />
                            <Badge size="sm" color={viewKeyModal.tokenActive ? 'green' : 'orange'} variant="dot">
                                Token {viewKeyModal.tokenDeviceCode || 'HSM'}: {viewKeyModal.tokenState}
                            </Badge>
                            <Badge size="sm" color="cyan" variant="light">{viewKeyModal.keyAlgorithm} {viewKeyModal.keySize}</Badge>
                        </Group>
                        <Text size="xs">Public Key SHA-1 (SKI): <Code>{viewKeyModal.publicKeySha1}</Code></Text>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" fw={700}>SubjectPublicKeyInfo (PEM) — Loaded from MariaDB (0 HSM calls)</Text>
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

            {/* Modal: View / Generate CSR */}
            <Modal
                opened={Boolean(csrModalSigner)}
                onClose={() => { setCsrModalSigner(null); setCsrData(null); setCsrAwaitingTokenChoice(false); }}
                title={<Group gap="xs"><IconFileCertificate size={20} color="#38bdf8" /><Text fw={700}>Signer CSR: {csrModalSigner?.name}</Text></Group>}
                size="lg"
            >
                {csrLoading ? (
                    <Group justify="center" p="xl"><Loader size="md" /></Group>
                ) : csrAwaitingTokenChoice && csrModalSigner ? (
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            if (csrTargetTokenId) executeCsrGeneration(csrModalSigner, csrTargetTokenId);
                        }}
                    >
                        <Stack gap="md">
                            <Alert color="cyan" variant="light">
                                Signer <b>{csrModalSigner.name}</b> is linked to <b>{(csrModalSigner.tokens || []).length} HSM Tokens</b>. Choose which unlocked token should generate the new keypair and sign the CSR.
                            </Alert>
                            <Select
                                label="Target HSM Crypto Token"
                                placeholder="Select an active HSM Token"
                                data={(csrModalSigner.tokens || []).map((t) => ({
                                    value: t.deviceId,
                                    label: `${t.deviceId} [${t.role}] · ${t.tokenLabel || 'slot ' + t.slotId} (${t.activationState === 'ACTIVE' ? 'ACTIVE' : 'DEACTIVATED / LOCKED'})`,
                                    disabled: t.activationState !== 'ACTIVE',
                                }))}
                                value={csrTargetTokenId}
                                onChange={(val) => setCsrTargetTokenId(val || '')}
                                required
                            />
                            <Group justify="flex-end">
                                <Button variant="default" onClick={() => { setCsrModalSigner(null); setCsrAwaitingTokenChoice(false); }}>Cancel</Button>
                                <Button type="submit" color="cyan" disabled={!csrTargetTokenId} leftSection={<IconFileCertificate size={15} />}>
                                    Generate Key &amp; CSR
                                </Button>
                            </Group>
                        </Stack>
                    </form>
                ) : csrData ? (
                    <Stack gap="md">
                        <Alert color="teal" variant="light">
                            Generated on Token <Code>{csrData.tokenDeviceId}</Code> · Key <Code>{csrData.keyLabel}</Code> ({csrData.keyAlgorithm} {csrData.keySize}) · <Code>{csrData.signatureAlgorithm}</Code>
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

            {/* Modal: View / Import Certificate */}
            <Modal
                opened={Boolean(certModalSigner)}
                onClose={() => { setCertModalSigner(null); setCertModalKey(null); setCertData(null); setCertPemInput(''); }}
                title={
                    <Group gap="xs">
                        <IconCertificate size={20} color="#6366f1" />
                        <Text fw={700}>
                            Signer Certificate: {certModalSigner?.name}
                            {certModalKey ? ` · Key #${certModalKey.id}` : ''}
                        </Text>
                    </Group>
                }
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
                            No certificate imported yet. Paste or upload the CA-signed PEM certificate (must include <Code>id-kp-OCSPSigning</Code> EKU per RFC 6960 §2.6; verified against <Code>ocsp_keys</Code> with zero HSM token calls).
                        </Alert>
                    )}

                    {canOperate && (
                        <>
                            <Divider label={certData ? 'Import Replacement Certificate' : 'Import Certificate (POST /signer/{id}/cert)'} labelPosition="center" />
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
                                            label="Activate signer immediately after import (auto-deactivates any other active key on the same token)"
                                            checked={certActivateNow}
                                            onChange={(e) => setCertActivateNow(e.currentTarget.checked)}
                                            color="green"
                                        />
                                    )}
                                    <Group justify="flex-end">
                                        <Button variant="default" onClick={() => setCertModalSigner(null)}>Close</Button>
                                        <Button type="submit" color="indigo" loading={certLoading} leftSection={<IconCertificate size={15} />}>
                                            Import Certificate
                                        </Button>
                                    </Group>
                                </Stack>
                            </form>
                        </>
                    )}
                </Stack>
            </Modal>

            {/* Modal: Quick Activate (Unlock) Crypto Token */}
            <Modal
                opened={Boolean(unlockDeviceId)}
                onClose={() => { setUnlockPin(''); setUnlockDeviceId(null); }}
                title={<Group gap="xs"><IconLockOpen size={20} color="#22c55e" /><Text fw={700}>Activate Crypto Token: {unlockDeviceId}</Text></Group>}
            >
                <form onSubmit={handleQuickUnlock}>
                    <Stack gap="md">
                        <Alert color="cyan" variant="light">
                            Enter the User PIN for <Code>{unlockDeviceId}</Code>. PIN is used once for <Code>C_Login</Code> and immediately wiped from memory.
                        </Alert>
                        <PasswordInput label="PKCS#11 User PIN" placeholder="Enter PIN" value={unlockPin} onChange={(e) => setUnlockPin(e.currentTarget.value)} autoFocus required />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => { setUnlockPin(''); setUnlockDeviceId(null); }}>Cancel</Button>
                            <Button type="submit" color="green" loading={saving} leftSection={<IconLockOpen size={16} />}>Activate Token</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>
        </Container>
    );
};
