import React, { useState, useEffect } from 'react';
import { Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon, Modal, TextInput, Textarea, Switch, Alert, Loader, Tooltip, } from '@mantine/core';
import { IconShieldCheck, IconPlus, IconRefresh, IconTrash, IconAlertCircle, IconCertificate, } from '@tabler/icons-react';
import { getTrustedCas, importTrustedCa, toggleTrustedCa, deleteTrustedCa } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const TrustedCasPage = () => {
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => typeof r === 'string' ? r : (r?.authority ?? ''));
    const canManage = roleNames.includes('ROLE_ADMIN');

    const [cas, setCas] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    const [importOpen, setImportOpen] = useState(false);
    const [alias, setAlias] = useState('');
    const [certificatePem, setCertificatePem] = useState('');

    const fetchCas = async () => {
        try {
            setLoading(true);
            setError(null);
            const list = await getTrustedCas();
            setCas(list);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load Trusted CAs');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchCas();
    }, []);

    const handleImport = async (e) => {
        e.preventDefault();
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await importTrustedCa(alias, certificatePem);
            setImportOpen(false);
            setAlias('');
            setCertificatePem('');
            setSuccess(`Trusted CA '${alias}' imported and hot-reloaded into memory (no restart required).`);
            await fetchCas();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to import Trusted CA');
        } finally {
            setSaving(false);
        }
    };

    const handleToggle = async (ca, enabled) => {
        try {
            setSaving(true);
            setError(null);
            await toggleTrustedCa(ca.id, enabled);
            setSuccess(`Trusted CA '${ca.alias}' ${enabled ? 'enabled' : 'disabled'} and hot-reloaded.`);
            await fetchCas();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to update Trusted CA');
        } finally {
            setSaving(false);
        }
    };

    const handleDelete = async (ca) => {
        if (!window.confirm(`Remove Trusted CA '${ca.alias}' from truststore?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteTrustedCa(ca.id);
            setSuccess(`Trusted CA '${ca.alias}' removed and truststore hot-reloaded.`);
            await fetchCas();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete Trusted CA');
        } finally {
            setSaving(false);
        }
    };

    return (
        <Container size="xl" py="md">
            <Stack gap="lg">
                <Group justify="space-between" align="flex-end">
                    <div>
                        <Group gap="xs">
                            <IconShieldCheck size={28} color="#2dd4bf" />
                            <Title order={2} c="white">Trusted CAs (mTLS Truststore)</Title>
                            <Badge color="teal" variant="light">HOT-RELOAD (NO RESTART)</Badge>
                        </Group>
                        <Text c="dimmed" size="sm" mt={4}>
                            Manage Certificate Authorities trusted to issue mTLS user certificates. Importing, toggling, or removing a CA updates the in-memory truststore immediately.
                        </Text>
                    </div>
                    <Group>
                        <Button variant="default" leftSection={<IconRefresh size={16} />} onClick={fetchCas} loading={loading}>
                            Refresh
                        </Button>
                        {canManage && (
                            <Button leftSection={<IconPlus size={16} />} onClick={() => setImportOpen(true)} color="teal">
                                Import Trusted CA
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
                    <Alert icon={<IconShieldCheck size={18} />} title="Success" color="teal" withCloseButton onClose={() => setSuccess(null)}>
                        {success}
                    </Alert>
                )}

                <Paper withBorder p="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)' }}>
                    {loading ? (
                        <Group justify="center" p="xl"><Loader /></Group>
                    ) : cas.length === 0 ? (
                        <Text c="dimmed" ta="center" py="xl">
                            No Trusted CAs imported yet. Import a CA certificate (CA:TRUE) to enable mTLS user certificate verification.
                        </Text>
                    ) : (
                        <Table.ScrollContainer minWidth={720}>
                            <Table striped highlightOnHover verticalSpacing="sm">
                                <Table.Thead>
                                    <Table.Tr>
                                        <Table.Th>Alias</Table.Th>
                                        <Table.Th>Subject DN</Table.Th>
                                        <Table.Th>SHA-256 Fingerprint</Table.Th>
                                        <Table.Th>Expires</Table.Th>
                                        <Table.Th>Status</Table.Th>
                                        {canManage && <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>}
                                    </Table.Tr>
                                </Table.Thead>
                                <Table.Tbody>
                                    {cas.map((ca) => (
                                        <Table.Tr key={ca.id}>
                                            <Table.Td>
                                                <Group gap="xs">
                                                    <IconCertificate size={16} color="#2dd4bf" />
                                                    <Text fw={600} size="sm" c="white">{ca.alias}</Text>
                                                </Group>
                                            </Table.Td>
                                            <Table.Td><Text size="xs">{ca.subjectDn}</Text></Table.Td>
                                            <Table.Td>
                                                <Text size="xs" truncate maw={180} title={ca.fingerprintSha256}>
                                                    <code>{ca.fingerprintSha256}</code>
                                                </Text>
                                            </Table.Td>
                                            <Table.Td>
                                                <Text size="xs" c={ca.expired ? 'red' : 'dimmed'}>
                                                    {ca.notAfter ? new Date(ca.notAfter).toLocaleDateString() : '—'}
                                                </Text>
                                            </Table.Td>
                                            <Table.Td>
                                                {ca.expired ? (
                                                    <Badge color="red" variant="filled" size="sm">EXPIRED</Badge>
                                                ) : (
                                                    <Badge color={ca.enabled ? 'teal' : 'gray'} variant="filled" size="sm">
                                                        {ca.enabled ? 'TRUSTED' : 'DISABLED'}
                                                    </Badge>
                                                )}
                                            </Table.Td>
                                            {canManage && (
                                                <Table.Td style={{ textAlign: 'right' }}>
                                                    <Group justify="flex-end" gap="xs">
                                                        <Tooltip label={ca.enabled ? 'Disable CA' : 'Enable CA'}>
                                                            <Switch
                                                                checked={ca.enabled}
                                                                disabled={saving}
                                                                onChange={(e) => handleToggle(ca, e.currentTarget.checked)}
                                                                color="teal"
                                                                size="sm"
                                                            />
                                                        </Tooltip>
                                                        <Tooltip label="Remove Trusted CA">
                                                            <ActionIcon variant="light" color="red" disabled={saving} onClick={() => handleDelete(ca)}>
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
                    )}
                </Paper>
            </Stack>

            <Modal opened={importOpen} onClose={() => setImportOpen(false)} title="Import Trusted CA Certificate" size="lg">
                <form onSubmit={handleImport}>
                    <Stack gap="md">
                        <TextInput
                            label="CA Alias"
                            placeholder="e.g. corporate-root-ca"
                            value={alias}
                            onChange={(e) => setAlias(e.currentTarget.value)}
                            required
                        />
                        <Textarea
                            label="CA Certificate (X.509 PEM, BasicConstraints CA:TRUE)"
                            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                            minRows={6}
                            value={certificatePem}
                            onChange={(e) => setCertificatePem(e.currentTarget.value)}
                            required
                        />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setImportOpen(false)}>Cancel</Button>
                            <Button type="submit" color="teal" loading={saving}>Import &amp; Trust Immediately</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>
        </Container>
    );
};

