import React, { useState, useEffect } from 'react'
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
  Switch,
  Alert,
  Loader,
  Tooltip,
  Code,
  Box,
  SimpleGrid,
  CopyButton,
} from '@mantine/core'
import {
  IconCertificate,
  IconPlus,
  IconRefresh,
  IconCheck,
  IconTrash,
  IconEye,
  IconAlertCircle,
  IconKey,
  IconShieldCheck,
  IconCopy,
} from '@tabler/icons-react'
import {
  getSigningCertificates,
  addSigningCertificate,
  activateSigningCertificate,
  deleteSigningCertificate,
} from '../api/client'
import type { SigningCertificateDto, AddSigningCertificateRequest } from '../types/api'

export const SigningCertificatesPage: React.FC = () => {
  const [certificates, setCertificates] = useState<SigningCertificateDto[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Add modal state
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [alias, setAlias] = useState('')
  const [keyLabel, setKeyLabel] = useState('ocsp-signing-key')
  const [certificatePem, setCertificatePem] = useState('')
  const [activateImmediately, setActivateImmediately] = useState(false)

  // View PEM modal state
  const [viewModalOpen, setViewModalOpen] = useState(false)
  const [selectedCert, setSelectedCert] = useState<SigningCertificateDto | null>(null)

  const fetchCertificates = async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getSigningCertificates()
      setCertificates(data)
    } catch (err: any) {
      setError(err?.response?.data?.message || err?.message || 'Failed to load signing certificates')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCertificates()
  }, [])

  const handleActivate = async (id: number, certAlias: string) => {
    try {
      setActionLoading(true)
      setError(null)
      await activateSigningCertificate(id)
      setSuccess(`Signing certificate '${certAlias}' is now active! All subsequent responses are signed with this certificate.`)
      await fetchCertificates()
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to activate certificate')
    } finally {
      setActionLoading(false)
    }
  }

  const handleDelete = async (id: number, certAlias: string) => {
    if (!window.confirm(`Are you sure you want to delete certificate '${certAlias}'?`)) {
      return
    }
    try {
      setActionLoading(true)
      setError(null)
      await deleteSigningCertificate(id)
      setSuccess(`Certificate '${certAlias}' deleted successfully.`)
      await fetchCertificates()
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete certificate')
    } finally {
      setActionLoading(false)
    }
  }

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!alias.trim() || !certificatePem.trim()) {
      setError('Please provide both an alias and certificate PEM')
      return
    }

    try {
      setActionLoading(true)
      setError(null)
      const payload: AddSigningCertificateRequest = {
        alias: alias.trim(),
        keyLabel: keyLabel.trim() || 'ocsp-signing-key',
        certificatePem: certificatePem.trim(),
        activateImmediately,
      }
      await addSigningCertificate(payload)
      setSuccess(`Signing certificate '${alias}' added successfully${activateImmediately ? ' and activated' : ''}.`)
      setAddModalOpen(false)
      setAlias('')
      setKeyLabel('ocsp-signing-key')
      setCertificatePem('')
      setActivateImmediately(false)
      await fetchCertificates()
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to register certificate')
    } finally {
      setActionLoading(false)
    }
  }

  const activeCert = certificates.find((c) => c.active)

  return (
    <Container size="xl" py="lg">
      <Stack gap="lg">
        {/* Header */}
        <Group justify="space-between" align="flex-start">
          <Box>
            <Title order={2} fw={800}>
              Signing Certificates Management
            </Title>
            <Text c="dimmed" size="sm">
              Configure and rotate cryptographic HSM signing certificates for RFC 6960 OCSP responses.
              Exactly one certificate is active at any time.
            </Text>
          </Box>
          <Group>
            <Button
              variant="default"
              leftSection={<IconRefresh size={16} />}
              onClick={fetchCertificates}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              variant="gradient"
              gradient={{ from: 'indigo.6', to: 'violet.6' }}
              leftSection={<IconPlus size={16} />}
              onClick={() => {
                setError(null)
                setAddModalOpen(true)
              }}
            >
              Add Signing Certificate
            </Button>
          </Group>
        </Group>

        {/* Notifications */}
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

        {/* Hero Card: Currently Active Signing Certificate */}
        {activeCert && (
          <Paper
            withBorder
            p="lg"
            radius="md"
            style={{
              background: 'linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(99, 102, 241, 0.08) 100%)',
              borderColor: 'rgba(34, 197, 94, 0.35)',
            }}
          >
            <Group justify="space-between" mb="xs">
              <Group gap="xs">
                <IconShieldCheck size={26} color="#22c55e" />
                <Title order={3} fw={700}>
                  Active Signing Certificate: {activeCert.alias}
                </Title>
              </Group>
              <Badge color="green" size="lg" variant="filled">
                ACTIVE SIGNER
              </Badge>
            </Group>

            <SimpleGrid cols={{ base: 1, md: 3 }} spacing="sm" mt="md">
              <Box>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Subject DN</Text>
                <Text size="sm" fw={600} style={{ wordBreak: 'break-all' }}>{activeCert.subjectDn}</Text>
              </Box>
              <Box>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Issuer DN</Text>
                <Text size="sm" fw={600} style={{ wordBreak: 'break-all' }}>{activeCert.issuerDn}</Text>
              </Box>
              <Box>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>HSM Key Label / Algorithm</Text>
                <Group gap="xs">
                  <Badge variant="outline" color="indigo">{activeCert.keyLabel}</Badge>
                  <Badge variant="light" color="cyan">{activeCert.signatureAlgorithm}</Badge>
                </Group>
              </Box>
              <Box>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Serial Number (Hex)</Text>
                <Code>{activeCert.serialNumber}</Code>
              </Box>
              <Box>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Validity Period</Text>
                <Text size="xs">
                  {new Date(activeCert.notBefore).toLocaleDateString()} – {new Date(activeCert.notAfter).toLocaleDateString()}
                </Text>
              </Box>
              <Box>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Lifecycle Status</Text>
                <Badge color={activeCert.daysUntilExpiry < 7 ? 'red' : activeCert.daysUntilExpiry < 30 ? 'orange' : 'teal'} variant="light">
                  {activeCert.expired ? 'Expired' : `${activeCert.daysUntilExpiry} days remaining`}
                </Badge>
              </Box>
            </SimpleGrid>
          </Paper>
        )}

        {/* Certificates Table */}
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between" mb="md">
            <Title order={4}>Registered Signing Certificates ({certificates.length})</Title>
          </Group>

          {loading ? (
            <Group justify="center" p="xl">
              <Loader size="md" />
            </Group>
          ) : certificates.length === 0 ? (
            <Text c="dimmed" ta="center" py="xl">
              No signing certificates found in registry.
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={800}>
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
                  {certificates.map((cert) => (
                    <Table.Tr key={cert.id} style={cert.active ? { backgroundColor: 'rgba(34, 197, 94, 0.05)' } : undefined}>
                      <Table.Td>
                        {cert.active ? (
                          <Badge color="green" variant="filled">
                            ACTIVE
                          </Badge>
                        ) : (
                          <Badge color="gray" variant="light">
                            STANDBY
                          </Badge>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Text fw={600} size="sm">{cert.alias}</Text>
                        <Text size="xs" c="dimmed" lineClamp={1}>{cert.subjectDn}</Text>
                      </Table.Td>
                      <Table.Td>
                        <Code>{cert.serialNumber}</Code>
                      </Table.Td>
                      <Table.Td>
                        <Badge variant="outline" color="indigo" size="sm">
                          {cert.keyLabel}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs">{new Date(cert.notAfter).toLocaleDateString()}</Text>
                        <Badge
                          size="xs"
                          color={cert.expired ? 'red' : cert.daysUntilExpiry < 7 ? 'red' : cert.daysUntilExpiry < 30 ? 'orange' : 'teal'}
                          variant="light"
                        >
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
                          {!cert.active && (
                            <Button
                              size="compact-xs"
                              variant="filled"
                              color="green"
                              leftSection={<IconCheck size={14} />}
                              loading={actionLoading}
                              disabled={cert.expired}
                              onClick={() => handleActivate(cert.id, cert.alias)}
                            >
                              Make Active
                            </Button>
                          )}
                          <Tooltip label="View Certificate PEM">
                            <ActionIcon
                              variant="light"
                              color="blue"
                              onClick={() => {
                                setSelectedCert(cert)
                                setViewModalOpen(true)
                              }}
                            >
                              <IconEye size={16} />
                            </ActionIcon>
                          </Tooltip>
                          {!cert.active && (
                            <Tooltip label="Delete certificate">
                              <ActionIcon
                                variant="light"
                                color="red"
                                loading={actionLoading}
                                onClick={() => handleDelete(cert.id, cert.alias)}
                              >
                                <IconTrash size={16} />
                              </ActionIcon>
                            </Tooltip>
                          )}
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

      {/* Modal: Add Signing Certificate */}
      <Modal
        opened={addModalOpen}
        onClose={() => setAddModalOpen(false)}
        title={
          <Group gap="xs">
            <IconCertificate size={20} color="#6366f1" />
            <Text fw={700}>Add New Signing Certificate</Text>
          </Group>
        }
        size="lg"
      >
        <form onSubmit={handleAddSubmit}>
          <Stack gap="md">
            <TextInput
              label="Certificate Alias"
              placeholder="e.g. ocsp-signing-2027"
              value={alias}
              onChange={(e) => setAlias(e.currentTarget.value)}
              required
            />

            <TextInput
              label="HSM Key Label / Alias"
              placeholder="ocsp-signing-key"
              description="The private key label in the HSM token corresponding to this certificate"
              leftSection={<IconKey size={16} />}
              value={keyLabel}
              onChange={(e) => setKeyLabel(e.currentTarget.value)}
              required
            />

            <Textarea
              label="Certificate PEM"
              placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"
              description="Paste the X.509 signing certificate in PEM format"
              minRows={6}
              maxRows={10}
              value={certificatePem}
              onChange={(e) => setCertificatePem(e.currentTarget.value)}
              required
            />

            <Switch
              label="Make active immediately"
              description="If checked, this certificate will immediately become the active signer for all OCSP responses"
              checked={activateImmediately}
              onChange={(e) => setActivateImmediately(e.currentTarget.checked)}
              color="green"
            />

            <Group justify="flex-end" mt="md">
              <Button variant="default" onClick={() => setAddModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} loading={actionLoading}>
                Add Certificate
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* Modal: View PEM */}
      <Modal
        opened={viewModalOpen}
        onClose={() => setViewModalOpen(false)}
        title={
          <Group justify="space-between" style={{ width: '100%' }}>
            <Text fw={700}>Certificate PEM: {selectedCert?.alias}</Text>
            {selectedCert && (
              <CopyButton value={selectedCert.certificatePem}>
                {({ copied, copy }) => (
                  <Button size="xs" color={copied ? 'teal' : 'indigo'} variant="light" leftSection={<IconCopy size={14} />} onClick={copy}>
                    {copied ? 'Copied' : 'Copy PEM'}
                  </Button>
                )}
              </CopyButton>
            )}
          </Group>
        }
        size="lg"
      >
        {selectedCert && (
          <Stack gap="sm">
            <Box p="xs" style={{ borderRadius: 6, backgroundColor: 'rgba(0,0,0,0.2)' }}>
              <Text size="xs" c="dimmed">Subject: <b>{selectedCert.subjectDn}</b></Text>
              <Text size="xs" c="dimmed">Issuer: <b>{selectedCert.issuerDn}</b></Text>
              <Text size="xs" c="dimmed">Serial: <code>{selectedCert.serialNumber}</code></Text>
            </Box>
            <Code block style={{ maxHeight: 300, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
              {selectedCert.certificatePem}
            </Code>
          </Stack>
        )}
      </Modal>
    </Container>
  )
}

