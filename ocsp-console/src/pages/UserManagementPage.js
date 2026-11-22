import React, { useState, useEffect } from 'react';
import { Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon, Modal, TextInput, PasswordInput, Textarea, MultiSelect, Switch, Alert, Loader, Tooltip, } from '@mantine/core';
import { IconUsers, IconPlus, IconRefresh, IconEdit, IconTrash, IconAlertCircle, IconShieldCheck, IconLock, IconUser, IconMail, IconId, IconKey, IconCertificate, } from '@tabler/icons-react';
import { getUsers, getRoles, createUser, updateUser, resetUserPassword, deleteUser, getUserCertificates, assignUserCertificate, removeUserCertificate } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const UserManagementPage = () => {
    const { user: currentUser, authConfig } = useAuth();
    const isKeycloak = !!authConfig?.isKeycloak;
    const [users, setUsers] = useState([]);
    const [roles, setRoles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    const [createOpen, setCreateOpen] = useState(false);
    const [newUsername, setNewUsername] = useState('');
    const [newEmail, setNewEmail] = useState('');
    const [newFullName, setNewFullName] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [newTenantId, setNewTenantId] = useState('default');
    const [newRoles, setNewRoles] = useState(['ROLE_AGENT']);
    const [newEnabled, setNewEnabled] = useState(true);

    const [editOpen, setEditOpen] = useState(false);
    const [editingUser, setEditingUser] = useState(null);
    const [editEmail, setEditEmail] = useState('');
    const [editFullName, setEditFullName] = useState('');
    const [editTenantId, setEditTenantId] = useState('default');
    const [editRoles, setEditRoles] = useState([]);
    const [editEnabled, setEditEnabled] = useState(true);
    const [editPassword, setEditPassword] = useState('');

    const [resetOpen, setResetOpen] = useState(false);
    const [resetTarget, setResetTarget] = useState(null);
    const [resetPasswordVal, setResetPasswordVal] = useState('');
    const [resetConfirmVal, setResetConfirmVal] = useState('');

    const [certsOpen, setCertsOpen] = useState(false);
    const [certsTarget, setCertsTarget] = useState(null);
    const [userCerts, setUserCerts] = useState([]);
    const [certsLoading, setCertsLoading] = useState(false);
    const [certPem, setCertPem] = useState('');

    const fetchAll = async () => {
        try {
            setLoading(true);
            setError(null);
            const [u, r] = await Promise.all([getUsers(), getRoles()]);
            setUsers(u);
            setRoles(r);
        } catch (err) {
            setError(err?.response?.data?.error || err?.response?.data?.message || 'Failed to load users (Admin role required)');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAll();
    }, []);

    const roleOptions = roles.map((r) => ({
        value: r.name,
        label: `${r.name.replace(/^ROLE_/, '')} — ${r.description || r.name}`,
    }));

    const handleCreate = async (e) => {
        e.preventDefault();
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await createUser({
                username: newUsername,
                email: newEmail || null,
                fullName: newFullName || null,
                password: isKeycloak ? null : newPassword,
                tenantId: newTenantId || 'default',
                roles: newRoles,
                enabled: newEnabled,
            });
            setCreateOpen(false);
            setNewUsername('');
            setNewEmail('');
            setNewFullName('');
            setNewPassword('');
            setNewTenantId('default');
            setNewRoles(['ROLE_AGENT']);
            setNewEnabled(true);
            setSuccess(`User '${newUsername}' created.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to create user');
        } finally {
            setSaving(false);
        }
    };

    const openEdit = (u) => {
        setEditingUser(u);
        setEditEmail(u.email || '');
        setEditFullName(u.fullName || '');
        setEditTenantId(u.tenantId || 'default');
        setEditRoles(u.roles || []);
        setEditEnabled(u.enabled);
        setEditPassword('');
        setEditOpen(true);
    };

    const handleUpdate = async (e) => {
        e.preventDefault();
        if (!editingUser) return;
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await updateUser(editingUser.id, {
                email: editEmail || null,
                fullName: editFullName || null,
                tenantId: editTenantId || 'default',
                roles: editRoles,
                enabled: editEnabled,
                password: !isKeycloak && editPassword.trim() ? editPassword : null,
            });
            setEditOpen(false);
            setSuccess(`User '${editingUser.username}' updated.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to update user');
        } finally {
            setSaving(false);
        }
    };

    const openResetPassword = (u) => {
        setResetTarget(u);
        setResetPasswordVal('');
        setResetConfirmVal('');
        setResetOpen(true);
    };

    const handleResetPassword = async (e) => {
        e.preventDefault();
        if (!resetTarget) return;
        if (!isKeycloak) {
            if (resetPasswordVal.length < 4) {
                setError('New password must be at least 4 characters');
                return;
            }
            if (resetPasswordVal !== resetConfirmVal) {
                setError('Passwords do not match');
                return;
            }
        }
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await resetUserPassword(resetTarget.id, isKeycloak ? null : resetPasswordVal);
            setResetOpen(false);
            setSuccess(
                isKeycloak
                    ? `Password reset email triggered in Keycloak for '${resetTarget.username}'.`
                    : `Password reset successfully for '${resetTarget.username}'.`
            );
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to reset password');
        } finally {
            setSaving(false);
        }
    };

    const openCertificates = async (u) => {
        setCertsTarget(u);
        setCertPem('');
        setCertsOpen(true);
        try {
            setCertsLoading(true);
            const list = await getUserCertificates(u.id);
            setUserCerts(list);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load user certificates');
        } finally {
            setCertsLoading(false);
        }
    };

    const handleAssignCertificate = async (e) => {
        e.preventDefault();
        if (!certsTarget || !certPem.trim()) return;
        try {
            setSaving(true);
            setError(null);
            await assignUserCertificate(certsTarget.id, certPem);
            setCertPem('');
            const list = await getUserCertificates(certsTarget.id);
            setUserCerts(list);
            setSuccess(`Assigned X.509 certificate to '${certsTarget.username}'.`);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to assign certificate');
        } finally {
            setSaving(false);
        }
    };

    const handleRemoveCertificate = async (certId) => {
        if (!certsTarget) return;
        try {
            setSaving(true);
            setError(null);
            await removeUserCertificate(certsTarget.id, certId);
            const list = await getUserCertificates(certsTarget.id);
            setUserCerts(list);
            setSuccess(`Removed certificate assignment from '${certsTarget.username}'.`);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to remove certificate');
        } finally {
            setSaving(false);
        }
    };

    const handleDelete = async (u) => {
        if (!window.confirm(`Soft-delete user '${u.username}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await deleteUser(u.id);
            setSuccess(`User '${u.username}' soft-deleted.`);
            await fetchAll();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete user');
        } finally {
            setSaving(false);
        }
    };

    const roleColor = (r) => {
        if (r === 'ROLE_ADMIN') return 'red';
        if (r === 'ROLE_AGENT') return 'indigo';
        return 'teal';
    };

    return (
        <Container size="xl" py="md">
            <Stack gap="lg">
                <Group justify="space-between" align="flex-end">
                    <div>
                        <Group gap="xs">
                            <IconUsers size={28} color="#818cf8" />
                            <Title order={2} c="white">User Management &amp; RBAC</Title>
                            <Badge color={isKeycloak ? 'orange' : 'indigo'} variant="light">
                                {isKeycloak ? 'KEYCLOAK MODE' : 'SELF_MANAGEMENT MODE'}
                            </Badge>
                        </Group>
                        <Text c="dimmed" size="sm" mt={4}>
                            {isKeycloak
                                ? 'Keycloak owns credentials and identity (DB holds a read-only replica keyed by external_id); app owns RBAC roles and tenant profile.'
                                : 'App DB owns credentials, identity, and RBAC roles.'}
                        </Text>
                    </div>
                    <Group>
                        <Button variant="default" leftSection={<IconRefresh size={16} />} onClick={fetchAll} loading={loading}>
                            Refresh
                        </Button>
                        <Button leftSection={<IconPlus size={16} />} onClick={() => setCreateOpen(true)} color="indigo">
                            Create User
                        </Button>
                    </Group>
                </Group>

                {error && (
                    <Alert icon={<IconAlertCircle size={18} />} title="Error" color="red" withCloseButton onClose={() => setError(null)}>
                        {error}
                    </Alert>
                )}
                {success && (
                    <Alert icon={<IconShieldCheck size={18} />} title="Success" color="green" withCloseButton onClose={() => setSuccess(null)}>
                        {success}
                    </Alert>
                )}

                <Paper withBorder p="md" radius="md" style={{ backgroundColor: 'var(--mantine-color-dark-6)' }}>
                    {loading ? (
                        <Group justify="center" py="xl"><Loader size="md" /></Group>
                    ) : (
                        <Table.ScrollContainer minWidth={850}>
                            <Table verticalSpacing="sm" highlightOnHover>
                                <Table.Thead>
                                    <Table.Tr>
                                        <Table.Th>Username / Name</Table.Th>
                                        <Table.Th>Email</Table.Th>
                                        <Table.Th>Source</Table.Th>
                                        <Table.Th>Tenant</Table.Th>
                                        <Table.Th>Roles</Table.Th>
                                        <Table.Th>Status</Table.Th>
                                        <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                    </Table.Tr>
                                </Table.Thead>
                                <Table.Tbody>
                                    {users.map((u) => (
                                        <Table.Tr key={u.id}>
                                            <Table.Td>
                                                <Group gap="xs">
                                                    <Text fw={600} size="sm" c="white">{u.username}</Text>
                                                    {currentUser?.username === u.username && (
                                                        <Badge size="xs" variant="outline" color="cyan">YOU</Badge>
                                                    )}
                                                </Group>
                                                {u.fullName && <Text size="xs" c="dimmed">{u.fullName}</Text>}
                                            </Table.Td>
                                            <Table.Td>
                                                <Text size="xs">{u.email || '—'}</Text>
                                            </Table.Td>
                                            <Table.Td>
                                                <Badge size="xs" color={u.authSource === 'KEYCLOAK' ? 'orange' : 'blue'} variant="light">
                                                    {u.authSource}
                                                </Badge>
                                            </Table.Td>
                                            <Table.Td>
                                                <Text size="xs" c="dimmed">{u.tenantId || 'default'}</Text>
                                            </Table.Td>
                                            <Table.Td>
                                                <Group gap={6}>
                                                    {(u.roles || []).map((r) => (
                                                        <Badge key={r} size="sm" color={roleColor(r)} variant="light">
                                                            {r.replace(/^ROLE_/, '')}
                                                        </Badge>
                                                    ))}
                                                </Group>
                                            </Table.Td>
                                            <Table.Td>
                                                <Badge color={u.enabled ? 'green' : 'gray'} variant="filled" size="sm">
                                                    {u.enabled ? 'ENABLED' : 'DISABLED'}
                                                </Badge>
                                            </Table.Td>
                                            <Table.Td style={{ textAlign: 'right' }}>
                                                <Group justify="flex-end" gap="xs">
                                                    <Tooltip label="Assign / Manage X.509 certificates (mTLS)">
                                                        <ActionIcon variant="light" color="teal" onClick={() => openCertificates(u)}>
                                                            <IconCertificate size={16} />
                                                        </ActionIcon>
                                                    </Tooltip>
                                                    <Tooltip label={isKeycloak ? 'Send Keycloak password reset email' : 'Reset password'}>
                                                        <ActionIcon variant="light" color="yellow" onClick={() => openResetPassword(u)}>
                                                            <IconKey size={16} />
                                                        </ActionIcon>
                                                    </Tooltip>
                                                    <Tooltip label="Edit user">
                                                        <ActionIcon variant="light" color="indigo" onClick={() => openEdit(u)}>
                                                            <IconEdit size={16} />
                                                        </ActionIcon>
                                                    </Tooltip>
                                                    <Tooltip label={currentUser?.username === u.username ? 'Cannot delete yourself' : 'Soft-delete user'}>
                                                        <ActionIcon
                                                            variant="light"
                                                            color="red"
                                                            disabled={saving || currentUser?.username === u.username}
                                                            onClick={() => handleDelete(u)}
                                                        >
                                                            <IconTrash size={16} />
                                                        </ActionIcon>
                                                    </Tooltip>
                                                </Group>
                                            </Table.Td>
                                        </Table.Tr>
                                    ))}
                                </Table.Tbody>
                            </Table>
                        </Table.ScrollContainer>
                    )}
                </Paper>
            </Stack>

            <Modal opened={createOpen} onClose={() => setCreateOpen(false)} title="Create New User" size="md">
                <form onSubmit={handleCreate}>
                    <Stack gap="md">
                        <TextInput label="Username" leftSection={<IconUser size={16} />} value={newUsername} onChange={(e) => setNewUsername(e.currentTarget.value)} required minLength={3} />
                        <TextInput label="Email" leftSection={<IconMail size={16} />} value={newEmail} onChange={(e) => setNewEmail(e.currentTarget.value)} type="email" />
                        <TextInput label="Full Name" leftSection={<IconId size={16} />} value={newFullName} onChange={(e) => setNewFullName(e.currentTarget.value)} />
                        {!isKeycloak && (
                            <PasswordInput label="Password" leftSection={<IconLock size={16} />} value={newPassword} onChange={(e) => setNewPassword(e.currentTarget.value)} required minLength={4} />
                        )}
                        <TextInput label="Tenant ID" value={newTenantId} onChange={(e) => setNewTenantId(e.currentTarget.value)} />
                        <MultiSelect label="Roles" data={roleOptions} value={newRoles} onChange={setNewRoles} required />
                        <Switch label="Account Enabled" checked={newEnabled} onChange={(e) => setNewEnabled(e.currentTarget.checked)} />
                        <Group justify="flex-end" mt="sm">
                            <Button variant="default" onClick={() => setCreateOpen(false)}>Cancel</Button>
                            <Button type="submit" color="indigo" loading={saving}>Create User</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            <Modal opened={editOpen} onClose={() => setEditOpen(false)} title={`Edit User: ${editingUser?.username || ''}`} size="md">
                <form onSubmit={handleUpdate}>
                    <Stack gap="md">
                        <TextInput label="Email" leftSection={<IconMail size={16} />} value={editEmail} onChange={(e) => setEditEmail(e.currentTarget.value)} type="email" />
                        <TextInput label="Full Name" leftSection={<IconId size={16} />} value={editFullName} onChange={(e) => setEditFullName(e.currentTarget.value)} />
                        <TextInput label="Tenant ID" value={editTenantId} onChange={(e) => setEditTenantId(e.currentTarget.value)} />
                        <MultiSelect label="Roles" data={roleOptions} value={editRoles} onChange={setEditRoles} required />
                        <Switch label="Account Enabled" checked={editEnabled} onChange={(e) => setEditEnabled(e.currentTarget.checked)} />
                        {!isKeycloak && (
                            <PasswordInput label="New Password (optional)" placeholder="Leave blank to keep current password" leftSection={<IconLock size={16} />} value={editPassword} onChange={(e) => setEditPassword(e.currentTarget.value)} />
                        )}
                        <Group justify="flex-end" mt="sm">
                            <Button variant="default" onClick={() => setEditOpen(false)}>Cancel</Button>
                            <Button type="submit" color="indigo" loading={saving}>Save Changes</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            <Modal opened={resetOpen} onClose={() => setResetOpen(false)} title={`Reset Password: ${resetTarget?.username || ''}`} size="md">
                <form onSubmit={handleResetPassword}>
                    <Stack gap="md">
                        {isKeycloak ? (
                            <Text size="sm" c="dimmed">
                                In KEYCLOAK mode, credentials are owned by Keycloak. Submitting will trigger a Keycloak
                                password-reset email (<code>UPDATE_PASSWORD</code>) for <strong>{resetTarget?.email || resetTarget?.username}</strong>.
                            </Text>
                        ) : (
                            <>
                                <PasswordInput
                                    label="New Password"
                                    leftSection={<IconLock size={16} />}
                                    value={resetPasswordVal}
                                    onChange={(e) => setResetPasswordVal(e.currentTarget.value)}
                                    required
                                    minLength={4}
                                />
                                <PasswordInput
                                    label="Confirm New Password"
                                    leftSection={<IconLock size={16} />}
                                    value={resetConfirmVal}
                                    onChange={(e) => setResetConfirmVal(e.currentTarget.value)}
                                    required
                                    minLength={4}
                                />
                            </>
                        )}
                        <Group justify="flex-end" mt="sm">
                            <Button variant="default" onClick={() => setResetOpen(false)}>Cancel</Button>
                            <Button type="submit" color="yellow" loading={saving}>
                                {isKeycloak ? 'Send Reset Email' : 'Reset Password'}
                            </Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            <Modal opened={certsOpen} onClose={() => setCertsOpen(false)} title={`User Certificates (Optional mTLS): ${certsTarget?.username || ''}`} size="lg">
                <Stack gap="md">
                    <Text size="xs" c="dimmed">
                        1-way TLS does not require user certificates. When mTLS client-certificate authentication is enabled (<code>security.tls.client-cert-auth-enabled=true</code>), assigned X.509 certificates authenticate this user by SHA-256 fingerprint.
                    </Text>
                    {certsLoading ? (
                        <Group justify="center" p="md"><Loader size="sm" /></Group>
                    ) : userCerts.length === 0 ? (
                        <Text size="sm" c="dimmed">No certificates assigned to this user.</Text>
                    ) : (
                        <Table striped withTableBorder>
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Serial (Hex)</Table.Th>
                                    <Table.Th>Subject DN</Table.Th>
                                    <Table.Th>SHA-256 Fingerprint</Table.Th>
                                    <Table.Th>Expires</Table.Th>
                                    <Table.Th />
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                                {userCerts.map((c) => (
                                    <Table.Tr key={c.id}>
                                        <Table.Td><code>{c.serialNumberHex}</code></Table.Td>
                                        <Table.Td><Text size="xs">{c.subjectDn}</Text></Table.Td>
                                        <Table.Td><Text size="xs" truncate maw={160} title={c.fingerprintSha256}><code>{c.fingerprintSha256}</code></Text></Table.Td>
                                        <Table.Td><Text size="xs">{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}</Text></Table.Td>
                                        <Table.Td>
                                            <ActionIcon color="red" variant="light" onClick={() => handleRemoveCertificate(c.id)} disabled={saving}>
                                                <IconTrash size={14} />
                                            </ActionIcon>
                                        </Table.Td>
                                    </Table.Tr>
                                ))}
                            </Table.Tbody>
                        </Table>
                    )}
                    <form onSubmit={handleAssignCertificate}>
                        <Stack gap="sm">
                            <Textarea
                                label="Assign New X.509 Certificate (PEM)"
                                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                                minRows={4}
                                value={certPem}
                                onChange={(e) => setCertPem(e.currentTarget.value)}
                                required
                            />
                            <Group justify="flex-end">
                                <Button variant="default" onClick={() => setCertsOpen(false)}>Close</Button>
                                <Button type="submit" color="teal" loading={saving}>Assign Certificate</Button>
                            </Group>
                        </Stack>
                    </form>
                </Stack>
            </Modal>
        </Container>
    );
};
