import React, { useState, useEffect } from 'react';
import { Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon, Modal, TextInput, PasswordInput, NumberInput, Select, Switch, Alert, Loader, Tooltip, Code, Box, SimpleGrid, } from '@mantine/core';
import { IconCpu, IconLock, IconLockOpen, IconPlus, IconRefresh, IconTrash, IconEdit, IconAlertCircle, IconCheck, IconServer, } from '@tabler/icons-react';
import { getCryptoProviders, getAllowedLibraryDirs, createCryptoProvider, updateCryptoProvider, deleteCryptoProvider, getCryptoDevices, createCryptoDevice, updateCryptoDevice, deleteCryptoDevice, activateCryptoDevice, deactivateCryptoDevice, } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const CryptoDevicesPage = () => {
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => typeof r === 'string' ? r : (r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');

    const [providers, setProviders] = useState([]);
    const [devices, setDevices] = useState([]);
    const [allowedDirs, setAllowedDirs] = useState([]);
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
    const [provWrapperPath, setProvWrapperPath] = useState('embedded');
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

    const fetchAll = async () => {
        try {
            setLoading(true);
            setError(null);
            const [provList, devList, dirs] = await Promise.all([
                getCryptoProviders(),
                getCryptoDevices(),
                getAllowedLibraryDirs().catch(() => []),
            ]);
            setProviders(provList);
            setDevices(devList);
            setAllowedDirs(dirs);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load HSM providers and devices');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAll();
    }, []);

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
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to lock HSM device');
        } finally {
            setSaving(false);
        }
    };

    const openCreateProvider = () => {
        setEditingProviderId(null);
        setProvCode('');
        setProvName('');
        setProvWrapperType('PKCS11J');
        setProvLibraryPath('/usr/lib/softhsm/libsofthsm2.so');
        setProvWrapperPath('embedded');
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
        setProvWrapperPath(p.libraryWrapperPath || 'embedded');
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
                libraryWrapperPath: provWrapperPath.trim() || 'embedded',
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
        setError(null);
        setDeviceModalOpen(true);
    };

    const handleDeviceSubmit = async (e) => {
        e.preventDefault();
        try {
            setSaving(true);
            setError(null);
            const parsedSlotId = devSlotId.trim() !== '' ? Number(devSlotId.trim()) : null;
            const payload = {
                deviceId: devId.trim(),
                providerId: Number(devProviderId),
                tokenLabel: devTokenLabel.trim() || null,
                slotId: Number.isFinite(parsedSlotId) ? parsedSlotId : null,
                slotListIndex: Number(devSlotIndex) || 0,
                poolSize: Number(devPoolSize) || 4,
                prehashInJvm: devPrehash,
                isDefault: devDefault,
                enabled: devEnabled,
            };
            if (editingDeviceId != null) {
                await updateCryptoDevice(editingDeviceId, payload);
                setSuccess(`Device '${payload.deviceId}' updated (unlock required if hardware settings changed).`);
            } else {
                await createCryptoDevice(payload);
                setSuccess(`Device '${payload.deviceId}' registered in LOCKED state. Click Unlock to activate it.`);
            }
            setDeviceModalOpen(false);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to save crypto device');
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteDevice = async (d) => {
        if (!window.confirm(`Delete crypto device '${d.deviceId}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteCryptoDevice(d.id);
            setSuccess(`Device '${d.deviceId}' deleted.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete crypto device');
        } finally {
            setSaving(false);
        }
    };

    const stateColor = (state) => state === 'ACTIVE' ? 'green' : state === 'ERROR' ? 'red' : 'orange';
    const providerSelectData = providers.map((p) => ({
        value: String(p.id),
        label: `${p.code} — ${p.name} (${p.wrapperType})`,
    }));

    return (
        <Container size="xl" py="md">
            <Stack gap="lg">
                <Group justify="space-between" align="flex-start" wrap="wrap">
                    <Box>
                        <Group gap="xs">
                            <IconCpu size={28} color="#38bdf8" />
                            <Title order={2} c="white">HSM Devices &amp; PKCS#11 Providers</Title>
                            <Badge color="cyan" variant="light">PATTERN 2 · ZERO PIN IN DB</Badge>
                        </Group>
                        <Text c="dimmed" size="sm" mt={4}>
                            Configure vendor PKCS#11 drivers (<Code>libraryPath</Code>) + JNI wrappers (<Code>libraryWrapperPath</Code>) and manage multi-device token slots.
                            No HSM PIN is ever stored in MariaDB or RAM: administrators unlock devices transiently at runtime.
                        </Text>
                    </Box>
                    <Group>
                        <Button variant="default" leftSection={<IconRefresh size={16} />} onClick={fetchAll} loading={loading}>
                            Refresh
                        </Button>
                        {isAdmin && (
                            <>
                                <Button variant="light" color="cyan" leftSection={<IconPlus size={16} />} onClick={openCreateProvider}>
                                    Add Provider
                                </Button>
                                <Button variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} leftSection={<IconPlus size={16} />} onClick={openCreateDevice} disabled={providers.length === 0}>
                                    Add HSM Device
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

                {/* Section 1: HSM Devices (Runtime Activation) */}
                <Paper withBorder p="md" radius="md">
                    <Group justify="space-between" mb="md">
                        <Title order={4}>HSM Signing Devices ({devices.length})</Title>
                        <Badge color="teal" variant="light">
                            {devices.filter((d) => d.activationState === 'ACTIVE').length} / {devices.length} Active
                        </Badge>
                    </Group>

                    {loading ? (
                        <Group justify="center" p="xl"><Loader size="md" /></Group>
                    ) : devices.length === 0 ? (
                        <Text c="dimmed" ta="center" py="lg">No crypto devices registered.</Text>
                    ) : (
                        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                            {devices.map((d) => (
                                <Paper key={d.id} withBorder p="md" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.45)' }}>
                                    <Group justify="space-between" mb="xs">
                                        <Group gap="xs">
                                            <Badge size="sm" color={d.isDefault ? 'blue' : 'gray'} variant="filled">
                                                {d.deviceId}
                                            </Badge>
                                            <Badge size="xs" color="cyan" variant="light">{d.wrapperType}</Badge>
                                            {d.isDefault && <Badge size="xs" color="indigo" variant="outline">DEFAULT</Badge>}
                                            {!d.enabled && <Badge size="xs" color="gray" variant="light">DISABLED</Badge>}
                                        </Group>
                                        <Badge size="sm" color={stateColor(d.activationState)} variant="dot">
                                            {d.activationState}
                                        </Badge>
                                    </Group>

                                    <Text size="xs" c="dimmed">
                                        Provider: <Code>{d.providerCode}</Code> · Token: <Code>{d.tokenLabel || 'by slot'}</Code> · Slot: <Code>{d.slotId != null ? d.slotId : `idx ${d.slotListIndex}`}</Code> · Pool: <Code>{d.poolSize}</Code>
                                    </Text>
                                    <Text size="xs" c="dimmed" mt={4}>
                                        Driver: <Code>{d.libraryPath}</Code> · Wrapper: <Code>{d.libraryWrapperPath}</Code>
                                    </Text>
                                    <Text size="xs" c="dimmed" mt={4}>
                                        Status: {d.statusMessage}
                                    </Text>

                                    <Group gap={4} mt="xs" wrap="wrap">
                                        {d.activationState === 'ACTIVE' ? (
                                            (d.keyLabels || []).length === 0
                                                ? <Text size="xs" c="dimmed">Unlocked (no keys on token yet)</Text>
                                                : d.keyLabels.map((k) => (
                                                    <Badge key={k} size="xs" variant="outline" color="indigo">
                                                        {k}{d.keyAlgorithms?.[k] ? ` (${d.keyAlgorithms[k]})` : ''}
                                                    </Badge>
                                                ))
                                        ) : (
                                            <Text size="xs" c="orange.4">Locked — unlock with HSM PIN to load slot keys &amp; sign</Text>
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
                </Paper>

                {/* Section 2: Cryptographic Providers (library + libraryWrapper) */}
                <Paper withBorder p="md" radius="md">
                    <Group justify="space-between" mb="xs">
                        <Group gap="xs">
                            <IconServer size={20} color="#818cf8" />
                            <Title order={4}>Cryptographic Providers ({providers.length})</Title>
                        </Group>
                        {allowedDirs.length > 0 && (
                            <Text size="xs" c="dimmed">
                                Allowlist dirs: <Code>{allowedDirs.join(', ')}</Code>
                            </Text>
                        )}
                    </Group>

                    <Table.ScrollContainer minWidth={800}>
                        <Table verticalSpacing="sm" highlightOnHover>
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Code</Table.Th>
                                    <Table.Th>Name</Table.Th>
                                    <Table.Th>Wrapper Type</Table.Th>
                                    <Table.Th>PKCS#11 Library</Table.Th>
                                    <Table.Th>Library Wrapper</Table.Th>
                                    <Table.Th>Devices</Table.Th>
                                    <Table.Th>Status</Table.Th>
                                    {isAdmin && <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>}
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                                {providers.map((p) => (
                                    <Table.Tr key={p.id}>
                                        <Table.Td><Code>{p.code}</Code></Table.Td>
                                        <Table.Td><Text size="sm" fw={600}>{p.name}</Text></Table.Td>
                                        <Table.Td><Badge size="xs" color="cyan" variant="light">{p.wrapperType}</Badge></Table.Td>
                                        <Table.Td><Code>{p.libraryPath}</Code></Table.Td>
                                        <Table.Td><Code>{p.libraryWrapperPath}</Code></Table.Td>
                                        <Table.Td><Badge size="xs" variant="outline">{p.deviceCount}</Badge></Table.Td>
                                        <Table.Td>
                                            <Badge size="xs" color={p.enabled ? 'teal' : 'gray'} variant="light">
                                                {p.enabled ? 'ENABLED' : 'DISABLED'}
                                            </Badge>
                                        </Table.Td>
                                        {isAdmin && (
                                            <Table.Td style={{ textAlign: 'right' }}>
                                                <Group justify="flex-end" gap="xs">
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
                                                </Group>
                                            </Table.Td>
                                        )}
                                    </Table.Tr>
                                ))}
                            </Table.Tbody>
                        </Table>
                    </Table.ScrollContainer>
                </Paper>
            </Stack>

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
                            <TextInput label="Provider Code" placeholder="thales-luna" value={provCode} onChange={(e) => setProvCode(e.currentTarget.value)} required />
                            <TextInput label="Display Name" placeholder="Thales Luna Network HSM" value={provName} onChange={(e) => setProvName(e.currentTarget.value)} required />
                        </SimpleGrid>
                        <Select
                            label="Wrapper Strategy"
                            data={[
                                { value: 'PKCS11J', label: 'PKCS11J (In-Process ipkcs11wrapper)' },
                            ]}
                            value={provWrapperType}
                            onChange={(val) => setProvWrapperType(val || 'PKCS11J')}
                            required
                        />
                        <TextInput
                            label="PKCS#11 Vendor Library Path (libraryPath)"
                            description="Absolute path inside hsm.allowed-library-dirs"
                            placeholder="/usr/lib/softhsm/libsofthsm2.so"
                            value={provLibraryPath}
                            onChange={(e) => setProvLibraryPath(e.currentTarget.value)}
                            required
                        />
                        <TextInput
                            label="JNI Library Wrapper Path (libraryWrapperPath)"
                            description="Use 'embedded' to load the bundled ipkcs11wrapper native library or supply an allowlisted custom path"
                            placeholder="embedded"
                            value={provWrapperPath}
                            onChange={(e) => setProvWrapperPath(e.currentTarget.value)}
                            required
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
            <Modal opened={deviceModalOpen} onClose={() => setDeviceModalOpen(false)} title={editingDeviceId != null ? 'Edit HSM Device' : 'Add HSM Device'} size="lg">
                <form onSubmit={handleDeviceSubmit}>
                    <Stack gap="md">
                        <SimpleGrid cols={2}>
                            <TextInput label="Device ID" placeholder="hsm-partition-2" value={devId} onChange={(e) => setDevId(e.currentTarget.value)} required />
                            <Select label="Provider (Driver + Wrapper)" data={providerSelectData} value={devProviderId} onChange={(val) => setDevProviderId(val || '')} required />
                        </SimpleGrid>
                        <SimpleGrid cols={2}>
                            <TextInput label="Token Label" description="Matches C_GetTokenInfo().label (optional if slotId set)" placeholder="ocsp-signing-2" value={devTokenLabel} onChange={(e) => setDevTokenLabel(e.currentTarget.value)} />
                            <TextInput label="Numeric Slot ID (optional)" placeholder="Leave blank to match by tokenLabel" value={devSlotId} onChange={(e) => setDevSlotId(e.currentTarget.value)} />
                        </SimpleGrid>
                        <SimpleGrid cols={2}>
                            <NumberInput label="Slot List Index Fallback" min={0} value={devSlotIndex} onChange={(val) => setDevSlotIndex(Number(val) || 0)} />
                            <NumberInput label="PKCS#11 RO Session Pool Size" min={1} max={64} value={devPoolSize} onChange={(val) => setDevPoolSize(Number(val) || 4)} />
                        </SimpleGrid>
                        <SimpleGrid cols={3}>
                            <Switch label="Pre-hash in JVM" checked={devPrehash} onChange={(e) => setDevPrehash(e.currentTarget.checked)} />
                            <Switch label="Default Device" checked={devDefault} onChange={(e) => setDevDefault(e.currentTarget.checked)} />
                            <Switch label="Enabled" checked={devEnabled} onChange={(e) => setDevEnabled(e.currentTarget.checked)} />
                        </SimpleGrid>
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

