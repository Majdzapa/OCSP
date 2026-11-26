import React, { useState, useEffect, useCallback } from 'react';
import {
    Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon,
    Modal, TextInput, PasswordInput, NumberInput, Select, Switch, Alert, Loader,
    Tooltip, Code, Box, SimpleGrid, Tabs, SegmentedControl, Divider,
} from '@mantine/core';
import {
    IconCpu, IconLock, IconLockOpen, IconPlus, IconRefresh, IconTrash, IconEdit,
    IconAlertCircle, IconCheck, IconServer, IconListSearch, IconSparkles, IconKey,
} from '@tabler/icons-react';
import {
    getCryptoProviders, getAllowedLibraryDirs, createCryptoProvider, updateCryptoProvider,
    deleteCryptoProvider, discoverCryptoProviderSlots, initializeCryptoProviderToken,
    getCryptoDevices, createCryptoDevice, updateCryptoDevice, deleteCryptoDevice,
    activateCryptoDevice, deactivateCryptoDevice, getOcspReadiness,
} from '../api/client';
import { useAuth } from '../context/AuthContext';

export const CryptoDevicesPage = () => {
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => typeof r === 'string' ? r : (r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');

    const [activeTab, setActiveTab] = useState('devices');
    const [providers, setProviders] = useState([]);
    const [devices, setDevices] = useState([]);
    const [allowedDirs, setAllowedDirs] = useState([]);
    const [readiness, setReadiness] = useState(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    // Unlock modal (transient PIN only)
    const [unlockTarget, setUnlockTarget] = useState(null);
    const [unlockPin, setUnlockPin] = useState('');

    // Provider modal (create / edit)
    const [providerModalOpen, setProviderModalOpen] = useState(false);
    const [editingProviderId, setEditingProviderId] = useState(null);
    const [provCode, setProvCode] = useState('');
    const [provName, setProvName] = useState('');
    const [provWrapperType, setProvWrapperType] = useState('PKCS11J');
    const [provLibraryPath, setProvLibraryPath] = useState('/usr/lib/softhsm/libsofthsm2.so');
    const [provWrapperPath, setProvWrapperPath] = useState('');
    const [provEnabled, setProvEnabled] = useState(true);

    // Device modal (create / edit)
    const [deviceModalOpen, setDeviceModalOpen] = useState(false);
    const [editingDeviceId, setEditingDeviceId] = useState(null);
    const [devId, setDevId] = useState('');
    const [devProviderId, setDevProviderId] = useState('');
    const [devTokenLabel, setDevTokenLabel] = useState('');
    const [devSlotId, setDevSlotId] = useState('');
    const [devSlotIndex, setDevSlotIndex] = useState(0);
    const [devPoolSize, setDevPoolSize] = useState(4);
    const [devPrehash, setDevPrehash] = useState(false);
    const [devDefault, setDevDefault] = useState(false);
    const [devEnabled, setDevEnabled] = useState(true);
    const [modalSlots, setModalSlots] = useState([]);
    const [modalSlotsLoading, setModalSlotsLoading] = useState(false);

    // Dedicated "Slots & Vslots" tab state
    const [selectedSlotProviderId, setSelectedSlotProviderId] = useState('');
    const [discoveredSlots, setDiscoveredSlots] = useState([]);
    const [slotsLoading, setSlotsLoading] = useState(false);
    const [slotsError, setSlotsError] = useState(null);

    // Create Vslot / Initialize Token modal state
    const [initModalOpen, setInitModalOpen] = useState(false);
    const [initProviderId, setInitProviderId] = useState('');
    const [initMode, setInitMode] = useState('vslot'); // 'vslot' (auto free slot) | 'slot' (explicit slotId)
    const [initSlotId, setInitSlotId] = useState('');
    const [initTokenLabel, setInitTokenLabel] = useState('');
    const [initSoPin, setInitSoPin] = useState('');
    const [initUserPin, setInitUserPin] = useState('');
    const [initRegisterDevice, setInitRegisterDevice] = useState(true);
    const [initDeviceId, setInitDeviceId] = useState('');
    const [initPoolSize, setInitPoolSize] = useState(4);
    const [initIsDefault, setInitIsDefault] = useState(false);
    const [initModalSlots, setInitModalSlots] = useState([]);

    const loadSlotsForProvider = useCallback(async (provId) => {
        if (!provId) {
            setDiscoveredSlots([]);
            return;
        }
        try {
            setSlotsLoading(true);
            setSlotsError(null);
            const slots = await discoverCryptoProviderSlots(Number(provId));
            setDiscoveredSlots(slots);
        } catch (err) {
            setSlotsError(err?.response?.data?.error || err?.message || 'Failed to scan PKCS#11 slots');
            setDiscoveredSlots([]);
        } finally {
            setSlotsLoading(false);
        }
    }, []);

    const fetchAll = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const [provList, devList, dirs, rdy] = await Promise.all([
                getCryptoProviders(),
                getCryptoDevices(),
                getAllowedLibraryDirs().catch(() => []),
                getOcspReadiness().catch(() => null),
            ]);
            setProviders(provList);
            setDevices(devList);
            setAllowedDirs(dirs);
            setReadiness(rdy);
            setSelectedSlotProviderId((prev) => {
                if (prev && provList.some((p) => String(p.id) === String(prev))) {
                    return prev;
                }
                return provList[0] ? String(provList[0].id) : '';
            });
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load HSM providers and devices');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAll();
    }, [fetchAll]);

    useEffect(() => {
        if (activeTab === 'slots' && selectedSlotProviderId) {
            loadSlotsForProvider(selectedSlotProviderId);
        }
    }, [activeTab, selectedSlotProviderId, loadSlotsForProvider]);

    const handleUnlockSubmit = async (e) => {
        e.preventDefault();
        if (!unlockTarget || !unlockPin) return;
        const pinToUse = unlockPin;
        setUnlockPin('');
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            const updated = await activateCryptoDevice(unlockTarget.deviceId, pinToUse);
            setUnlockTarget(null);
            setSuccess(`Device '${updated.deviceId}' unlocked cleanly via C_Login (PIN wiped from RAM) and is now ACTIVE.`);
            await fetchAll();
            if (activeTab === 'slots' && selectedSlotProviderId) {
                await loadSlotsForProvider(selectedSlotProviderId);
            }
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to unlock HSM device');
        } finally {
            setSaving(false);
        }
    };

    const handleLockDevice = async (deviceId) => {
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await deactivateCryptoDevice(deviceId);
            setSuccess(`Device '${deviceId}' locked via C_Logout and sessions closed.`);
            await fetchAll();
            if (activeTab === 'slots' && selectedSlotProviderId) {
                await loadSlotsForProvider(selectedSlotProviderId);
            }
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to lock HSM device');
        } finally {
            setSaving(false);
        }
    };

    // ---- Provider CRUD ----
    const openCreateProvider = () => {
        setEditingProviderId(null);
        setProvCode('');
        setProvName('');
        setProvWrapperType('PKCS11J');
        setProvLibraryPath('/usr/lib/softhsm/libsofthsm2.so');
        setProvWrapperPath('');
        setProvEnabled(true);
        setError(null);
        setProviderModalOpen(true);
    };

    const openEditProvider = (p) => {
        setEditingProviderId(p.id);
        setProvCode(p.code);
        setProvName(p.name);
        setProvWrapperType(p.wrapperType || 'PKCS11J');
        setProvLibraryPath(p.libraryPath || '');
        setProvWrapperPath(p.libraryWrapperPath || '');
        setProvEnabled(Boolean(p.enabled));
        setError(null);
        setProviderModalOpen(true);
    };

    const handleProviderSubmit = async (e) => {
        e.preventDefault();
        try {
            setSaving(true);
            setError(null);
            const payload = {
                code: provCode.trim(),
                name: provName.trim(),
                wrapperType: provWrapperType,
                libraryPath: provLibraryPath.trim(),
                libraryWrapperPath: provWrapperPath.trim() || null,
                enabled: provEnabled,
            };
            if (editingProviderId != null) {
                await updateCryptoProvider(editingProviderId, payload);
                setSuccess(`Provider '${payload.code}' updated.`);
            } else {
                await createCryptoProvider(payload);
                setSuccess(`Provider '${payload.code}' created.`);
            }
            setProviderModalOpen(false);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to save crypto provider');
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteProvider = async (p) => {
        if (!window.confirm(`Delete crypto provider '${p.code}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteCryptoProvider(p.id);
            setSuccess(`Provider '${p.code}' deleted.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete crypto provider');
        } finally {
            setSaving(false);
        }
    };

    // ---- Create Vslot / Initialize Token ----
    const openInitTokenModal = async (providerObj = null, targetSlot = null) => {
        const provId = providerObj
            ? String(providerObj.id)
            : (selectedSlotProviderId || (providers[0] ? String(providers[0].id) : ''));
        setInitProviderId(provId);
        setInitMode(targetSlot != null ? 'slot' : 'vslot');
        setInitSlotId(targetSlot != null ? String(targetSlot.slotId) : '');
        setInitTokenLabel(targetSlot?.tokenLabel && targetSlot.initialized ? targetSlot.tokenLabel : '');
        setInitSoPin('');
        setInitUserPin('');
        setInitRegisterDevice(targetSlot == null || !targetSlot.configuredDeviceId);
        setInitDeviceId('');
        setInitPoolSize(4);
        setInitIsDefault(false);
        setError(null);
        setInitModalOpen(true);

        if (provId) {
            try {
                const slots = await discoverCryptoProviderSlots(Number(provId));
                setInitModalSlots(slots);
            } catch {
                setInitModalSlots([]);
            }
        }
    };

    const handleInitProviderChange = async (nextProvId) => {
        const clean = nextProvId || '';
        setInitProviderId(clean);
        setInitSlotId('');
        if (clean) {
            try {
                const slots = await discoverCryptoProviderSlots(Number(clean));
                setInitModalSlots(slots);
            } catch {
                setInitModalSlots([]);
            }
        } else {
            setInitModalSlots([]);
        }
    };

    const handleInitTokenSubmit = async (e) => {
        e.preventDefault();
        if (!initProviderId || !initTokenLabel.trim() || !initSoPin || !initUserPin) return;
        const soPinVal = initSoPin;
        const userPinVal = initUserPin;
        setInitSoPin('');
        setInitUserPin('');
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            const payload = {
                slotId: initMode === 'slot' && initSlotId !== '' ? Number(initSlotId) : null,
                tokenLabel: initTokenLabel.trim(),
                soPin: soPinVal,
                userPin: userPinVal,
                registerAsDevice: initRegisterDevice,
                deviceId: initRegisterDevice && initDeviceId.trim() ? initDeviceId.trim() : null,
                poolSize: initRegisterDevice ? Number(initPoolSize) || 4 : null,
                isDefault: initRegisterDevice ? initIsDefault : false,
            };
            const res = await initializeCryptoProviderToken(Number(initProviderId), payload);
            setInitModalOpen(false);
            setSuccess(res.message || `Token '${payload.tokenLabel}' initialized successfully.`);
            await fetchAll();
            setSelectedSlotProviderId(String(initProviderId));
            await loadSlotsForProvider(String(initProviderId));
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to initialize PKCS#11 token / Vslot');
        } finally {
            setSaving(false);
        }
    };

    // ---- Device CRUD ----
    const suggestDeviceId = (providerCode, tokenLabel, slotId) => {
        const base = (tokenLabel || `slot-${slotId}`).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
        return providerCode ? `${providerCode}-${base}` : base;
    };

    const handleScanModalSlots = async () => {
        if (!devProviderId) return;
        try {
            setModalSlotsLoading(true);
            setError(null);
            const slots = await discoverCryptoProviderSlots(Number(devProviderId));
            setModalSlots(slots);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to scan provider PKCS#11 slots');
        } finally {
            setModalSlotsLoading(false);
        }
    };

    const applySlotToDeviceForm = (slot, provider, fillIdIfBlank = false) => {
        setDevTokenLabel(slot.tokenLabel || '');
        setDevSlotId(slot.tokenLabel ? '' : String(slot.slotId));
        setDevSlotIndex(slot.slotListIndex ?? 0);
        if (fillIdIfBlank && !devId.trim()) {
            setDevId(suggestDeviceId(provider?.code, slot.tokenLabel, slot.slotId));
        }
    };

    const openCreateDeviceFromSlot = (slot, provider) => {
        setEditingDeviceId(null);
        setDevId(suggestDeviceId(provider?.code, slot.tokenLabel, slot.slotId));
        setDevProviderId(String(provider.id));
        setDevTokenLabel(slot.tokenLabel || '');
        setDevSlotId(slot.tokenLabel ? '' : String(slot.slotId));
        setDevSlotIndex(slot.slotListIndex ?? 0);
        setDevPoolSize(4);
        setDevPrehash(false);
        setDevDefault(false);
        setDevEnabled(true);
        setModalSlots(discoveredSlots);
        setError(null);
        setDeviceModalOpen(true);
    };

    const openCreateDevice = () => {
        setEditingDeviceId(null);
        setDevId('');
        setDevProviderId(providers[0] ? String(providers[0].id) : '');
        setDevTokenLabel('');
        setDevSlotId('');
        setDevSlotIndex(0);
        setDevPoolSize(4);
        setDevPrehash(false);
        setDevDefault(false);
        setDevEnabled(true);
        setModalSlots([]);
        setError(null);
        setDeviceModalOpen(true);
    };

    const openEditDevice = (d) => {
        setEditingDeviceId(d.id);
        setDevId(d.deviceId);
        setDevProviderId(String(d.providerId));
        setDevTokenLabel(d.tokenLabel || '');
        setDevSlotId(d.slotId != null ? String(d.slotId) : '');
        setDevSlotIndex(d.slotListIndex ?? 0);
        setDevPoolSize(d.poolSize ?? 4);
        setDevPrehash(Boolean(d.prehashInJvm));
        setDevDefault(Boolean(d.isDefault));
        setDevEnabled(Boolean(d.enabled));
        setModalSlots([]);
        setError(null);
        setDeviceModalOpen(true);
    };

    const handleDeviceSubmit = async (e) => {
        e.preventDefault();
        try {
            setSaving(true);
            setError(null);
            const payload = {
                deviceId: devId.trim(),
                providerId: Number(devProviderId),
                tokenLabel: devTokenLabel.trim() || null,
                slotId: devSlotId !== '' ? Number(devSlotId) : null,
                slotListIndex: Number(devSlotIndex) || 0,
                poolSize: Number(devPoolSize) || 4,
                prehashInJvm: devPrehash,
                isDefault: devDefault,
                enabled: devEnabled,
            };
            if (editingDeviceId != null) {
                await updateCryptoDevice(editingDeviceId, payload);
                setSuccess(`Device '${payload.deviceId}' updated (starts in LOCKED state — unlock with PIN).`);
            } else {
                await createCryptoDevice(payload);
                setSuccess(`Device '${payload.deviceId}' created in LOCKED state (zero PIN persisted).`);
            }
            setDeviceModalOpen(false);
            await fetchAll();
            if (activeTab === 'slots' && selectedSlotProviderId) {
                await loadSlotsForProvider(selectedSlotProviderId);
            }
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to save HSM device');
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteDevice = async (d) => {
        if (!window.confirm(`Delete HSM device '${d.deviceId}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteCryptoDevice(d.id);
            setSuccess(`Device '${d.deviceId}' deleted.`);
            await fetchAll();
            if (activeTab === 'slots' && selectedSlotProviderId) {
                await loadSlotsForProvider(selectedSlotProviderId);
            }
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete HSM device');
        } finally {
            setSaving(false);
        }
    };

    const stateColor = (state) => {
        if (state === 'ACTIVE') return 'green';
        if (state === 'ERROR') return 'red';
        return 'orange';
    };

    const providerSelectData = providers.map((p) => ({
        value: String(p.id),
        label: `${p.code} — ${p.name} (${p.wrapperType})`,
    }));

    const selectedSlotsProviderObj = providers.find((p) => String(p.id) === String(selectedSlotProviderId));
    const initProviderObj = providers.find((p) => String(p.id) === String(initProviderId));
    const selectedInitSlotObj = initModalSlots.find((s) => String(s.slotId) === String(initSlotId));
    const suggestedInitDevId = initTokenLabel.trim()
        ? suggestDeviceId(initProviderObj?.code, initTokenLabel.trim(), initSlotId || 'new')
        : 'auto-generated';

    return (
        <Container size="xl" py="md">
            <Stack gap="md">
                {/* Clean Header */}
                <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
                    <Box>
                        <Group gap="xs">
                            <IconCpu size={26} color="#38bdf8" />
                            <Title order={2} c="white">HSM Devices &amp; Virtual Slots</Title>
                            <Badge color="cyan" variant="light" size="sm">PATTERN 2 · ZERO PIN IN DB</Badge>
                        </Group>
                        <Text c="dimmed" size="sm" mt={2}>
                            Manage HSM providers, initialize virtual slots (Vslots) &amp; tokens, and unlock signing devices at runtime.
                        </Text>
                    </Box>
                    <Group gap="xs">
                        <Button variant="default" size="sm" leftSection={<IconRefresh size={15} />} onClick={() => { fetchAll(); if (activeTab === 'slots' && selectedSlotProviderId) loadSlotsForProvider(selectedSlotProviderId); }} loading={loading}>
                            Refresh
                        </Button>
                        {isAdmin && (
                            <>
                                <Button variant="light" color="teal" size="sm" leftSection={<IconSparkles size={15} />} onClick={() => openInitTokenModal()} disabled={providers.length === 0}>
                                    Create Vslot / Init Token
                                </Button>
                                <Button variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} size="sm" leftSection={<IconPlus size={15} />} onClick={openCreateDevice} disabled={providers.length === 0}>
                                    Add Device
                                </Button>
                            </>
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

                {/* Compact Pattern A Readiness Gate Strip */}
                {readiness && (
                    <Paper
                        withBorder
                        px="md"
                        py="xs"
                        radius="md"
                        style={{
                            borderColor: readiness.ocspReady ? 'rgba(34,197,94,0.4)' : 'rgba(245,158,11,0.5)',
                            backgroundColor: readiness.ocspReady ? 'rgba(34,197,94,0.06)' : 'rgba(245,158,11,0.08)',
                        }}
                    >
                        <Group justify="space-between" wrap="wrap" gap="xs">
                            <Group gap="xs">
                                <IconServer size={18} color={readiness.ocspReady ? '#22c55e' : '#f59e0b'} />
                                <Text fw={600} fz="sm" c="white">OCSP Readiness (<Code>/ocsp/health</Code>)</Text>
                                <Badge color={readiness.ocspReady ? 'teal' : 'orange'} variant="filled" size="sm">
                                    HTTP {readiness.httpStatus} · {readiness.status}
                                </Badge>
                                <Badge color="indigo" variant="light" size="sm">Node: {readiness.nodeId}</Badge>
                            </Group>
                            <Text fz="xs" c="dimmed">{readiness.detail}</Text>
                        </Group>
                    </Paper>
                )}

                {/* Clean 3-Tab Workspace */}
                <Tabs value={activeTab} onChange={(val) => setActiveTab(val || 'devices')} variant="outline" radius="md">
                    <Tabs.List mb="md">
                        <Tabs.Tab value="devices" leftSection={<IconCpu size={15} />}>
                            HSM Devices ({devices.length})
                            <Badge ml={6} size="xs" color="teal" variant="light">
                                {devices.filter((d) => d.activationState === 'ACTIVE').length} active
                            </Badge>
                        </Tabs.Tab>
                        <Tabs.Tab value="slots" leftSection={<IconSparkles size={15} />}>
                            Slots &amp; Vslots (Initialize Token)
                        </Tabs.Tab>
                        <Tabs.Tab value="providers" leftSection={<IconServer size={15} />}>
                            PKCS#11 Providers ({providers.length})
                        </Tabs.Tab>
                    </Tabs.List>

                    {/* TAB 1: HSM DEVICES (LOCK / UNLOCK) */}
                    <Tabs.Panel value="devices">
                        {loading ? (
                            <Group justify="center" p="xl"><Loader size="md" /></Group>
                        ) : devices.length === 0 ? (
                            <Paper withBorder p="xl" radius="md" ta="center">
                                <Text c="dimmed" mb="md">No HSM signing devices registered yet.</Text>
                                {isAdmin && providers.length > 0 && (
                                    <Button variant="light" color="teal" leftSection={<IconSparkles size={15} />} onClick={() => openInitTokenModal()}>
                                        Create Vslot &amp; Register First Device
                                    </Button>
                                )}
                            </Paper>
                        ) : (
                            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                                {devices.map((d) => (
                                    <Paper key={d.id} withBorder p="md" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.45)' }}>
                                        <Group justify="space-between" mb="xs">
                                            <Group gap="xs">
                                                <Badge size="sm" color={d.isDefault ? 'blue' : 'gray'} variant="filled">{d.deviceId}</Badge>
                                                <Badge size="xs" color="cyan" variant="light">{d.wrapperType}</Badge>
                                                {d.isDefault && <Badge size="xs" color="indigo" variant="outline">DEFAULT</Badge>}
                                                {!d.enabled && <Badge size="xs" color="gray" variant="light">DISABLED</Badge>}
                                            </Group>
                                            <Badge size="sm" color={stateColor(d.activationState)} variant="dot">{d.activationState}</Badge>
                                        </Group>

                                        <Text size="xs" c="dimmed">
                                            Provider: <Code>{d.providerCode}</Code> · Token: <Code>{d.tokenLabel || 'by slot'}</Code> · Slot: <Code>{d.slotId != null ? d.slotId : `idx ${d.slotListIndex}`}</Code> · Pool: <Code>{d.poolSize}</Code>
                                        </Text>
                                        <Text size="xs" c="dimmed" mt={4}>
                                            Driver: <Code>{d.libraryPath}</Code> · Wrapper: <Code>{d.libraryWrapperPath || 'built-in'}</Code>
                                        </Text>

                                        <Group gap={4} mt="xs" wrap="wrap">
                                            {d.activationState === 'ACTIVE' ? (
                                                (d.keyLabels || []).length === 0
                                                    ? <Text size="xs" c="dimmed">Unlocked — ready to generate CSRs</Text>
                                                    : d.keyLabels.map((k) => (
                                                        <Badge key={k} size="xs" variant="outline" color="indigo" leftSection={<IconKey size={10} />}>
                                                            {k}{d.keyAlgorithms?.[k] ? ` (${d.keyAlgorithms[k]})` : ''}
                                                        </Badge>
                                                    ))
                                            ) : (
                                                <Text size="xs" c="orange.4">Locked — click Unlock (PIN) to activate</Text>
                                            )}
                                        </Group>

                                        {isAdmin && (
                                            <Group justify="flex-end" gap="xs" mt="md">
                                                {d.activationState === 'ACTIVE' ? (
                                                    <Button size="compact-xs" variant="light" color="orange" leftSection={<IconLock size={14} />} loading={saving} onClick={() => handleLockDevice(d.deviceId)}>
                                                        Lock
                                                    </Button>
                                                ) : (
                                                    <Button size="compact-xs" variant="filled" color="green" leftSection={<IconLockOpen size={14} />} disabled={!d.enabled} onClick={() => { setError(null); setUnlockPin(''); setUnlockTarget(d); }}>
                                                        Unlock (PIN)
                                                    </Button>
                                                )}
                                                <Tooltip label="Edit device">
                                                    <ActionIcon variant="light" color="blue" onClick={() => openEditDevice(d)}>
                                                        <IconEdit size={16} />
                                                    </ActionIcon>
                                                </Tooltip>
                                                <Tooltip label="Delete device">
                                                    <ActionIcon variant="light" color="red" loading={saving} onClick={() => handleDeleteDevice(d)}>
                                                        <IconTrash size={16} />
                                                    </ActionIcon>
                                                </Tooltip>
                                            </Group>
                                        )}
                                    </Paper>
                                ))}
                            </SimpleGrid>
                        )}
                    </Tabs.Panel>

                    {/* TAB 2: SLOTS & VSLOTS (CREATE VSLOT / INITIALIZE TOKEN) */}
                    <Tabs.Panel value="slots">
                        <Paper withBorder p="md" radius="md">
                            <Stack gap="md">
                                <Group justify="space-between" align="flex-end" wrap="wrap" gap="sm">
                                    <Select
                                        label="Select PKCS#11 Provider"
                                        placeholder="Choose provider"
                                        data={providerSelectData}
                                        value={selectedSlotProviderId}
                                        onChange={(val) => setSelectedSlotProviderId(val || '')}
                                        style={{ minWidth: 280 }}
                                    />
                                    <Group gap="xs">
                                        <Button
                                            variant="default"
                                            size="sm"
                                            leftSection={<IconRefresh size={15} />}
                                            loading={slotsLoading}
                                            onClick={() => loadSlotsForProvider(selectedSlotProviderId)}
                                            disabled={!selectedSlotProviderId}
                                        >
                                            Scan Slots
                                        </Button>
                                        {isAdmin && (
                                            <Button
                                                variant="gradient"
                                                gradient={{ from: 'teal.6', to: 'cyan.6' }}
                                                size="sm"
                                                leftSection={<IconSparkles size={15} />}
                                                onClick={() => openInitTokenModal(selectedSlotsProviderObj, null)}
                                                disabled={!selectedSlotProviderId}
                                            >
                                                Create New Vslot
                                            </Button>
                                        )}
                                    </Group>
                                </Group>

                                <Alert color="cyan" variant="light" py="xs">
                                    <Text size="xs">
                                        Click <b>Create New Vslot</b> to initialize a free slot via PKCS#11 <Code>C_InitToken</Code> + <Code>C_InitPIN</Code> (on SoftHSM2 this creates a new virtual token slot automatically), or pick any slot below to initialize or register it as an OCSP signing device.
                                    </Text>
                                </Alert>

                                {slotsError && (
                                    <Alert icon={<IconAlertCircle size={16} />} color="red" title="Slot scan failed">
                                        {slotsError}
                                    </Alert>
                                )}

                                {slotsLoading ? (
                                    <Group justify="center" p="xl"><Loader size="md" /></Group>
                                ) : discoveredSlots.length === 0 ? (
                                    <Text c="dimmed" ta="center" py="lg">No PKCS#11 slots detected for this provider.</Text>
                                ) : (
                                    <Box style={{ overflowX: 'auto' }}>
                                        <Table verticalSpacing="sm" highlightOnHover miw={760}>
                                            <Table.Thead>
                                                <Table.Tr>
                                                    <Table.Th>Slot ID</Table.Th>
                                                    <Table.Th>Token Label</Table.Th>
                                                    <Table.Th>Model / Serial</Table.Th>
                                                    <Table.Th>Token State</Table.Th>
                                                    <Table.Th>OCSP Device</Table.Th>
                                                    <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                                </Table.Tr>
                                            </Table.Thead>
                                            <Table.Tbody>
                                                {discoveredSlots.map((slot) => (
                                                    <Table.Tr key={`${slot.slotId}-${slot.slotListIndex}`}>
                                                        <Table.Td>
                                                            <Code>{slot.slotId}</Code>
                                                            <Text size="10px" c="dimmed">index {slot.slotListIndex}</Text>
                                                        </Table.Td>
                                                        <Table.Td>
                                                            {slot.tokenLabel ? <Code>{slot.tokenLabel}</Code> : <Text size="xs" c="dimmed">Unlabeled</Text>}
                                                        </Table.Td>
                                                        <Table.Td>
                                                            <Text size="xs">{slot.model || '—'}</Text>
                                                            <Text size="11px" c="dimmed">{slot.serialNumber || 'No serial'}</Text>
                                                        </Table.Td>
                                                        <Table.Td>
                                                            <Badge size="xs" color={slot.initialized ? 'teal' : 'orange'} variant="light">
                                                                {slot.initialized ? 'INITIALIZED' : 'FREE / UNINITIALIZED'}
                                                            </Badge>
                                                        </Table.Td>
                                                        <Table.Td>
                                                            {slot.configuredDeviceId ? (
                                                                <Group gap={6} wrap="nowrap">
                                                                    <Badge size="xs" color="indigo" variant="filled">{slot.configuredDeviceId}</Badge>
                                                                    {slot.configuredDeviceState && (
                                                                        <Badge size="xs" color={stateColor(slot.configuredDeviceState)} variant="dot">
                                                                            {slot.configuredDeviceState}
                                                                        </Badge>
                                                                    )}
                                                                </Group>
                                                            ) : (
                                                                <Text size="xs" c="dimmed">Not registered</Text>
                                                            )}
                                                        </Table.Td>
                                                        <Table.Td style={{ textAlign: 'right' }}>
                                                            {isAdmin && (
                                                                <Group justify="flex-end" gap="xs" wrap="nowrap">
                                                                    {!slot.initialized ? (
                                                                        <Button
                                                                            size="compact-xs"
                                                                            color="teal"
                                                                            variant="filled"
                                                                            leftSection={<IconSparkles size={13} />}
                                                                            onClick={() => openInitTokenModal(selectedSlotsProviderObj, slot)}
                                                                        >
                                                                            Initialize Token
                                                                        </Button>
                                                                    ) : (
                                                                        <>
                                                                            {!slot.configuredDeviceId && (
                                                                                <Button
                                                                                    size="compact-xs"
                                                                                    variant="light"
                                                                                    color="indigo"
                                                                                    leftSection={<IconPlus size={13} />}
                                                                                    onClick={() => openCreateDeviceFromSlot(slot, selectedSlotsProviderObj)}
                                                                                >
                                                                                    Register Device
                                                                                </Button>
                                                                            )}
                                                                            <Tooltip label={slot.configuredDeviceState === 'ACTIVE' ? 'Lock device before re-initializing' : 'Re-initialize token (wipes keys on this slot)'}>
                                                                                <Button
                                                                                    size="compact-xs"
                                                                                    variant="subtle"
                                                                                    color="orange"
                                                                                    disabled={slot.configuredDeviceState === 'ACTIVE'}
                                                                                    onClick={() => openInitTokenModal(selectedSlotsProviderObj, slot)}
                                                                                >
                                                                                    Re-init
                                                                                </Button>
                                                                            </Tooltip>
                                                                        </>
                                                                    )}
                                                                </Group>
                                                            )}
                                                        </Table.Td>
                                                    </Table.Tr>
                                                ))}
                                            </Table.Tbody>
                                        </Table>
                                    </Box>
                                )}
                            </Stack>
                        </Paper>
                    </Tabs.Panel>

                    {/* TAB 3: CRYPTOGRAPHIC PROVIDERS */}
                    <Tabs.Panel value="providers">
                        <Paper withBorder p="md" radius="md">
                            <Group justify="space-between" mb="sm" wrap="wrap" gap="xs">
                                <Box>
                                    <Title order={4}>Configured PKCS#11 Drivers</Title>
                                    {allowedDirs.length > 0 && (
                                        <Text size="xs" c="dimmed">Allowlist dirs: <Code>{allowedDirs.join(', ')}</Code></Text>
                                    )}
                                </Box>
                                {isAdmin && (
                                    <Button variant="light" color="cyan" size="xs" leftSection={<IconPlus size={14} />} onClick={openCreateProvider}>
                                        Add Provider
                                    </Button>
                                )}
                            </Group>

                            <Box style={{ overflowX: 'auto' }}>
                                <Table verticalSpacing="sm" highlightOnHover miw={780}>
                                    <Table.Thead>
                                        <Table.Tr>
                                            <Table.Th>Code</Table.Th>
                                            <Table.Th>Name</Table.Th>
                                            <Table.Th>Library Path</Table.Th>
                                            <Table.Th>JNI Wrapper</Table.Th>
                                            <Table.Th>Devices</Table.Th>
                                            <Table.Th>Status</Table.Th>
                                            <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                        </Table.Tr>
                                    </Table.Thead>
                                    <Table.Tbody>
                                        {providers.map((p) => (
                                            <Table.Tr key={p.id}>
                                                <Table.Td><Code>{p.code}</Code></Table.Td>
                                                <Table.Td><Text size="sm" fw={600}>{p.name}</Text></Table.Td>
                                                <Table.Td><Code>{p.libraryPath}</Code></Table.Td>
                                                <Table.Td><Code>{p.libraryWrapperPath || 'built-in'}</Code></Table.Td>
                                                <Table.Td><Badge size="xs" variant="outline">{p.deviceCount}</Badge></Table.Td>
                                                <Table.Td>
                                                    <Badge size="xs" color={p.enabled ? 'teal' : 'gray'} variant="light">
                                                        {p.enabled ? 'ENABLED' : 'DISABLED'}
                                                    </Badge>
                                                </Table.Td>
                                                <Table.Td style={{ textAlign: 'right' }}>
                                                    <Group justify="flex-end" gap="xs" wrap="nowrap">
                                                        <Button
                                                            size="compact-xs"
                                                            variant="light"
                                                            color="cyan"
                                                            leftSection={<IconListSearch size={14} />}
                                                            onClick={() => {
                                                                setSelectedSlotProviderId(String(p.id));
                                                                setActiveTab('slots');
                                                            }}
                                                        >
                                                            Slots &amp; Vslots
                                                        </Button>
                                                        {isAdmin && (
                                                            <>
                                                                <Tooltip label="Edit provider">
                                                                    <ActionIcon variant="light" color="blue" onClick={() => openEditProvider(p)}>
                                                                        <IconEdit size={16} />
                                                                    </ActionIcon>
                                                                </Tooltip>
                                                                <Tooltip label="Delete provider">
                                                                    <ActionIcon variant="light" color="red" disabled={p.deviceCount > 0} onClick={() => handleDeleteProvider(p)}>
                                                                        <IconTrash size={16} />
                                                                    </ActionIcon>
                                                                </Tooltip>
                                                            </>
                                                        )}
                                                    </Group>
                                                </Table.Td>
                                            </Table.Tr>
                                        ))}
                                    </Table.Tbody>
                                </Table>
                            </Box>
                        </Paper>
                    </Tabs.Panel>
                </Tabs>
            </Stack>

            {/* Modal: Create Vslot / Initialize Token (Simple & Clear) */}
            <Modal
                opened={initModalOpen}
                onClose={() => { setInitSoPin(''); setInitUserPin(''); setInitModalOpen(false); }}
                title={
                    <Group gap="xs">
                        <IconSparkles size={20} color="#14b8a6" />
                        <Text fw={700}>Create Virtual Slot (Vslot) / Initialize Token</Text>
                    </Group>
                }
                size="lg"
            >
                <form onSubmit={handleInitTokenSubmit}>
                    <Stack gap="md">
                        <Select
                            label="PKCS#11 Provider"
                            data={providerSelectData}
                            value={initProviderId}
                            onChange={handleInitProviderChange}
                            required
                        />

                        <Box>
                            <Text size="sm" fw={500} mb={6}>Initialization Mode</Text>
                            <SegmentedControl
                                fullWidth
                                value={initMode}
                                onChange={(val) => {
                                    setInitMode(val);
                                    if (val === 'vslot') setInitSlotId('');
                                }}
                                data={[
                                    { label: 'Create New Virtual Slot (Auto Free Slot)', value: 'vslot' },
                                    { label: 'Initialize Specific Slot ID', value: 'slot' },
                                ]}
                            />
                        </Box>

                        {initMode === 'slot' && (
                            <>
                                <Select
                                    label="Target PKCS#11 Slot"
                                    placeholder="Select a slot"
                                    data={initModalSlots.map((s) => ({
                                        value: String(s.slotId),
                                        label: `Slot ${s.slotId} (idx ${s.slotListIndex}) — ${s.initialized ? `INITIALIZED: ${s.tokenLabel}` : 'FREE / UNINITIALIZED'}`,
                                    }))}
                                    value={initSlotId}
                                    onChange={(val) => setInitSlotId(val || '')}
                                    searchable
                                    required
                                />
                                {selectedInitSlotObj?.initialized && (
                                    <Alert color="orange" icon={<IconAlertCircle size={16} />} title="Re-initialization Warning">
                                        Slot <Code>{selectedInitSlotObj.slotId}</Code> (<Code>{selectedInitSlotObj.tokenLabel}</Code>) is already initialized. Re-initializing it erases all existing keys on that token and requires the existing SO PIN.
                                    </Alert>
                                )}
                            </>
                        )}

                        <TextInput
                            label="Token Label"
                            description="Human-readable label stored on the HSM token (1–32 characters)"
                            placeholder="e.g. ocsp-ca-3"
                            maxLength={32}
                            value={initTokenLabel}
                            onChange={(e) => setInitTokenLabel(e.currentTarget.value)}
                            required
                        />

                        <SimpleGrid cols={2}>
                            <PasswordInput
                                label="Security Officer (SO) PIN"
                                description="Used once for C_InitToken & C_Login(CKU_SO)"
                                placeholder="e.g. 12345678"
                                value={initSoPin}
                                onChange={(e) => setInitSoPin(e.currentTarget.value)}
                                required
                            />
                            <PasswordInput
                                label="Normal User PIN"
                                description="Set via C_InitPIN (used later to unlock)"
                                placeholder="e.g. 1234"
                                value={initUserPin}
                                onChange={(e) => setInitUserPin(e.currentTarget.value)}
                                required
                            />
                        </SimpleGrid>

                        <Alert color="cyan" variant="light" py="xs">
                            <Text size="xs">
                                <b>Zero-PIN Pattern 2:</b> Both SO PIN and User PIN are wiped from memory immediately after <Code>C_InitToken</Code> + <Code>C_InitPIN</Code> and are never persisted to MariaDB.
                            </Text>
                        </Alert>

                        <Divider />

                        <Switch
                            label="Also register as an OCSP Signing Device (LOCKED)"
                            description="Automatically adds this token to your HSM Devices list so you can unlock it and generate CSRs immediately"
                            checked={initRegisterDevice}
                            onChange={(e) => setInitRegisterDevice(e.currentTarget.checked)}
                            color="teal"
                        />

                        {initRegisterDevice && (
                            <SimpleGrid cols={2}>
                                <TextInput
                                    label="Device ID (optional)"
                                    placeholder={suggestedInitDevId}
                                    value={initDeviceId}
                                    onChange={(e) => setInitDeviceId(e.currentTarget.value)}
                                />
                                <NumberInput
                                    label="Session Pool Size"
                                    min={1}
                                    max={32}
                                    value={initPoolSize}
                                    onChange={(v) => setInitPoolSize(Number(v) || 4)}
                                />
                            </SimpleGrid>
                        )}

                        {initRegisterDevice && (
                            <Switch
                                label="Set as Default OCSP Signing Device"
                                checked={initIsDefault}
                                onChange={(e) => setInitIsDefault(e.currentTarget.checked)}
                            />
                        )}

                        <Group justify="flex-end" mt="xs">
                            <Button variant="default" onClick={() => { setInitSoPin(''); setInitUserPin(''); setInitModalOpen(false); }}>
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                color="teal"
                                loading={saving}
                                leftSection={<IconSparkles size={16} />}
                                disabled={initMode === 'slot' && !initSlotId}
                            >
                                {initMode === 'vslot' ? 'Create Vslot & Initialize Token' : 'Initialize Token'}
                            </Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            {/* Modal: Unlock Device (Runtime PIN) */}
            <Modal opened={Boolean(unlockTarget)} onClose={() => { setUnlockPin(''); setUnlockTarget(null); }} title={<Group gap="xs"><IconLockOpen size={20} color="#22c55e" /><Text fw={700}>Unlock HSM Device: {unlockTarget?.deviceId}</Text></Group>}>
                <form onSubmit={handleUnlockSubmit}>
                    <Stack gap="md">
                        <Alert color="cyan" variant="light">
                            The PIN is sent once to <Code>C_Login</Code> and immediately wiped from RAM (never written to MariaDB).
                        </Alert>
                        <PasswordInput
                            label="PKCS#11 User PIN"
                            placeholder="Enter token user PIN"
                            value={unlockPin}
                            onChange={(e) => setUnlockPin(e.currentTarget.value)}
                            autoFocus
                            required
                        />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => { setUnlockPin(''); setUnlockTarget(null); }}>Cancel</Button>
                            <Button type="submit" color="green" loading={saving} leftSection={<IconLockOpen size={16} />}>Unlock Device</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            {/* Modal: Create/Edit Provider */}
            <Modal opened={providerModalOpen} onClose={() => setProviderModalOpen(false)} title={editingProviderId != null ? 'Edit Cryptographic Provider' : 'Add Cryptographic Provider'} size="lg">
                <form onSubmit={handleProviderSubmit}>
                    <Stack gap="md">
                        <SimpleGrid cols={2}>
                            <TextInput label="Provider Code" placeholder="utimaco-r3" value={provCode} onChange={(e) => setProvCode(e.currentTarget.value)} required />
                            <TextInput label="Display Name" placeholder="Utimaco CryptoServer R3" value={provName} onChange={(e) => setProvName(e.currentTarget.value)} required />
                        </SimpleGrid>
                        <Select
                            label="Wrapper Strategy"
                            data={[{ value: 'PKCS11J', label: 'PKCS11J (In-Process ipkcs11wrapper)' }]}
                            value={provWrapperType}
                            onChange={(val) => setProvWrapperType(val || 'PKCS11J')}
                            required
                        />
                        <TextInput
                            label="PKCS#11 Vendor Library Path"
                            description="Absolute path inside hsm.allowed-library-dirs"
                            placeholder="/usr/lib/softhsm/libsofthsm2.so"
                            value={provLibraryPath}
                            onChange={(e) => setProvLibraryPath(e.currentTarget.value)}
                            required
                        />
                        <TextInput
                            label="JNI Library Wrapper Path (optional)"
                            description="Leave blank to use ipkcs11wrapper's built-in OS/arch loader"
                            placeholder="built-in (auto-detected)"
                            value={provWrapperPath}
                            onChange={(e) => setProvWrapperPath(e.currentTarget.value)}
                        />
                        <Switch label="Enabled" checked={provEnabled} onChange={(e) => setProvEnabled(e.currentTarget.checked)} />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setProviderModalOpen(false)}>Cancel</Button>
                            <Button type="submit" loading={saving}>Save Provider</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            {/* Modal: Create/Edit Device */}
            <Modal opened={deviceModalOpen} onClose={() => setDeviceModalOpen(false)} title={editingDeviceId != null ? `Edit HSM Device: ${devId}` : 'Register HSM Signing Device'} size="lg">
                <form onSubmit={handleDeviceSubmit}>
                    <Stack gap="md">
                        <Alert color="indigo" variant="light" py="xs">
                            No PIN field here by design — devices register in <Code>LOCKED</Code> state and are unlocked transiently at runtime.
                        </Alert>
                        <SimpleGrid cols={2}>
                            <TextInput label="Device ID" placeholder="softhsm-ca2" value={devId} onChange={(e) => setDevId(e.currentTarget.value)} required />
                            <Select
                                label="Cryptographic Provider"
                                data={providerSelectData}
                                value={devProviderId}
                                onChange={(val) => {
                                    setDevProviderId(val || '');
                                    setModalSlots([]);
                                }}
                                required
                            />
                        </SimpleGrid>

                        <Group justify="space-between" align="flex-end" wrap="wrap" gap="xs">
                            <Select
                                style={{ flex: 1, minWidth: 260 }}
                                label="Pick from Live Discovered Slots (optional)"
                                placeholder={modalSlots.length > 0 ? 'Select a slot to auto-fill' : 'Click "Scan Slots" to list live tokens'}
                                data={modalSlots.map((s) => ({
                                    value: String(s.slotId),
                                    label: `Slot ${s.slotId} (idx ${s.slotListIndex}) — ${s.tokenLabel || 'unlabeled'}${s.configuredDeviceId ? ` [mapped: ${s.configuredDeviceId}]` : ''}`,
                                }))}
                                value={modalSlots.find((s) => (s.tokenLabel && s.tokenLabel === devTokenLabel) || String(s.slotId) === String(devSlotId)) ? String(modalSlots.find((s) => (s.tokenLabel && s.tokenLabel === devTokenLabel) || String(s.slotId) === String(devSlotId)).slotId) : null}
                                onChange={(val) => {
                                    const picked = modalSlots.find((s) => String(s.slotId) === val);
                                    if (picked) {
                                        const prov = providers.find((p) => String(p.id) === String(devProviderId));
                                        applySlotToDeviceForm(picked, prov, true);
                                    }
                                }}
                                disabled={modalSlots.length === 0}
                                searchable
                            />
                            <Button variant="light" color="cyan" leftSection={<IconListSearch size={15} />} loading={modalSlotsLoading} disabled={!devProviderId} onClick={handleScanModalSlots}>
                                Scan Slots
                            </Button>
                        </Group>

                        <SimpleGrid cols={3}>
                            <TextInput label="Token Label" placeholder="ocsp-signing" value={devTokenLabel} onChange={(e) => setDevTokenLabel(e.currentTarget.value)} />
                            <TextInput label="Explicit Slot ID (optional)" placeholder="auto by label" value={devSlotId} onChange={(e) => setDevSlotId(e.currentTarget.value)} />
                            <NumberInput label="Slot List Index" min={0} value={devSlotIndex} onChange={(v) => setDevSlotIndex(Number(v) || 0)} />
                        </SimpleGrid>

                        <SimpleGrid cols={2}>
                            <NumberInput label="Session Pool Size" min={1} max={32} value={devPoolSize} onChange={(v) => setDevPoolSize(Number(v) || 4)} />
                            <Stack gap="xs" justify="center" pt="md">
                                <Switch label="Pre-hash in JVM (for legacy HSMs)" checked={devPrehash} onChange={(e) => setDevPrehash(e.currentTarget.checked)} />
                            </Stack>
                        </SimpleGrid>

                        <Group>
                            <Switch label="Default Signing Device" checked={devDefault} onChange={(e) => setDevDefault(e.currentTarget.checked)} />
                            <Switch label="Enabled" checked={devEnabled} onChange={(e) => setDevEnabled(e.currentTarget.checked)} />
                        </Group>

                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setDeviceModalOpen(false)}>Cancel</Button>
                            <Button type="submit" loading={saving}>Save Device</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>
        </Container>
    );
};
