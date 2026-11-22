import React, { useState, useEffect } from 'react';
import { Container, Paper, Title, Text, Group, Stack, Button, Badge, Table, ActionIcon, Modal, TextInput, PasswordInput, MultiSelect, Switch, Alert, Loader, Tooltip, } from '@mantine/core';
import { IconUsers, IconPlus, IconRefresh, IconEdit, IconTrash, IconAlertCircle, IconShieldCheck, IconLock, IconUser, } from '@tabler/icons-react';
import { getUsers, getRoles, createUser, updateUser, deleteUser } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const UserManagementPage = () => {
    const { user: currentUser } = useAuth();
    const [users, setUsers] = useState([]);
    const [roles, setRoles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    const [createOpen, setCreateOpen] = useState(false);
    const [newUsername, setNewUsername] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [newRoles, setNewRoles] = useState(['ROLE_AGENT']);
    const [newEnabled, setNewEnabled] = useState(true);

    const [editOpen, setEditOpen] = useState(false);
    const [editingUser, setEditingUser] = useState(null);
    const [editRoles, setEditRoles] = useState([]);
    const [editEnabled, setEditEnabled] = useState(true);
    const [editPassword, setEditPassword] = useState('');

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
                password: newPassword,
                roles: newRoles,
                enabled: newEnabled,
            });
            setCreateOpen(false);
            setNewUsername('');
            setNewPassword('');
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
                roles: editRoles,
                enabled: editEnabled,
                password: editPassword.trim() ? editPassword : null,
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

    const handleDelete = async (u) => {
        if (!window.confirm(`Delete user '${u.username}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            setSuccess(null);
            await deleteUser(u.id);
            setSuccess(`User '${u.username}' deleted.`);
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
                        </Group>
                        <Text c="dimmed" size="sm" mt={4}>
                            Admin-only management of local users and role assignments (ADMIN, AGENT, AUDITOR)
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
                        <Table.ScrollContainer minWidth={700}>
                            <Table verticalSpacing="sm" highlightOnHover>
                                <Table.Thead>
                                    <Table.Tr>
                                        <Table.Th>ID</Table.Th>
                                        <Table.Th>Username</Table.Th>
                                        <Table.Th>Roles</Table.Th>
                                        <Table.Th>Status</Table.Th>
                                        <Table.Th>Created</Table.Th>
                                        <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                    </Table.Tr>
                                </Table.Thead>
                                <Table.Tbody>
                                    {users.map((u) => (
                                        <Table.Tr key={u.id}>
                                            <Table.Td>{u.id}</Table.Td>
                                            <Table.Td>
                                                <Group gap="xs">
                                                    <Text fw={600} size="sm" c="white">{u.username}</Text>
                                                    {currentUser?.username === u.username && (
                                                        <Badge size="xs" variant="outline" color="cyan">YOU</Badge>
                                                    )}
                                                </Group>
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
                                            <Table.Td>
                                                <Text size="xs" c="dimmed">
                                                    {u.createdAt ? new Date(u.createdAt).toLocaleString() : '—'}
                                                </Text>
                                            </Table.Td>
                                            <Table.Td style={{ textAlign: 'right' }}>
                                                <Group justify="flex-end" gap="xs">
                                                    <Tooltip label="Edit user">
                                                        <ActionIcon variant="light" color="indigo" onClick={() => openEdit(u)}>
                                                            <IconEdit size={16} />
                                                        </ActionIcon>
                                                    </Tooltip>
                                                    <Tooltip label={currentUser?.username === u.username ? 'Cannot delete yourself' : 'Delete user'}>
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
                        <TextInput
                            label="Username"
                            leftSection={<IconUser size={16} />}
                            value={newUsername}
                            onChange={(e) => setNewUsername(e.currentTarget.value)}
                            required
                            minLength={3}
                        />
                        <PasswordInput
                            label="Password"
                            leftSection={<IconLock size={16} />}
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.currentTarget.value)}
                            required
                            minLength={4}
                        />
                        <MultiSelect
                            label="Roles"
                            data={roleOptions}
                            value={newRoles}
                            onChange={setNewRoles}
                            required
                        />
                        <Switch
                            label="Account Enabled"
                            checked={newEnabled}
                            onChange={(e) => setNewEnabled(e.currentTarget.checked)}
                        />
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
                        <MultiSelect
                            label="Roles"
                            data={roleOptions}
                            value={editRoles}
                            onChange={setEditRoles}
                            required
                        />
                        <Switch
                            label="Account Enabled"
                            checked={editEnabled}
                            onChange={(e) => setEditEnabled(e.currentTarget.checked)}
                        />
                        <PasswordInput
                            label="New Password (optional)"
                            placeholder="Leave blank to keep current password"
                            leftSection={<IconLock size={16} />}
                            value={editPassword}
                            onChange={(e) => setEditPassword(e.currentTarget.value)}
                        />
                        <Group justify="flex-end" mt="sm">
                            <Button variant="default" onClick={() => setEditOpen(false)}>Cancel</Button>
                            <Button type="submit" color="indigo" loading={saving}>Save Changes</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>
        </Container>
    );
};

