import React, { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Container,
  Paper,
  Title,
  Text,
  TextInput,
  PasswordInput,
  Textarea,
  Button,
  Alert,
  Group,
  Stack,
  ThemeIcon,
  Tabs,
  Badge,
  Code,
  Box,
  Divider,
} from '@mantine/core'
import {
  IconLock,
  IconKey,
  IconUser,
  IconShieldLock,
  IconAlertCircle,
  IconArrowRight,
  IconBrandOauth,
  IconExternalLink,
  IconUsersGroup,
} from '@tabler/icons-react'
import { useAuth } from '../context/AuthContext'

export const LoginPage: React.FC = () => {
  const {
    login,
    loginWithKey,
    loginWithToken,
    loginWithCert,
    setTlsActive,
    authConfig,
  } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const isKeycloak = !!authConfig?.isKeycloak
  const isTlsActive = authConfig?.tlsEnabled !== false
  const [activeTab, setActiveTab] = useState<string | null>(
    isKeycloak ? 'keycloak-sso' : 'creds'
  )
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('changeme')
  const [apiKey, setApiKey] = useState('incert-admin-secret-key')
  const [bearerToken, setBearerToken] = useState('')
  const [clientCertPem, setClientCertPem] = useState('CN=admin,O=Incert Certificate Authority,C=LU')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [togglingTls, setTogglingTls] = useState(false)

  const from = (location.state as any)?.from?.pathname || '/dashboard'

  // Handle OAuth2 Implicit Flow redirect back from Keycloak:
  // Keycloak appends: #access_token=eyJhbGci...&token_type=Bearer...
  useEffect(() => {
    const hash = window.location.hash
    if (hash && hash.includes('access_token=')) {
      const hashParams = new URLSearchParams(hash.replace(/^#/, ''))
      const token = hashParams.get('access_token')
      if (token) {
        setLoading(true)
        loginWithToken(token)
          .then(() => {
            // Remove token from browser address bar for security
            window.history.replaceState(null, '', window.location.pathname)
            navigate(from, { replace: true })
          })
          .catch((err: any) => {
            setError(err?.message || 'Failed to authenticate token received from Keycloak')
            setLoading(false)
          })
      }
    }
  }, [location.hash, loginWithToken, navigate, from])

  // Update default tab once authConfig is resolved
  useEffect(() => {
    if (authConfig?.isKeycloak && activeTab === 'creds') {
      setActiveTab('keycloak-sso')
    }
  }, [authConfig?.isKeycloak])

  const redirectToKeycloak = () => {
    const authServerUrl = authConfig?.keycloak?.authServerUrl || 'http://localhost:8081'
    const realm = authConfig?.keycloak?.realm || 'incert'
    const clientId = authConfig?.keycloak?.clientId || 'ocsp-console'
    const redirectUri = encodeURIComponent(`${window.location.origin}/login`)

    // Keycloak standard OpenID Connect authorization endpoint
    const ssoUrl = `${authServerUrl}/realms/${realm}/protocol/openid-connect/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=token&scope=openid%20profile%20email`
    window.location.href = ssoUrl
  }

  const handleToggleTls = async () => {
    setTogglingTls(true)
    setError(null)
    try {
      await setTlsActive(!isTlsActive)
    } catch (err: any) {
      setError(err?.response?.data?.message || err?.message || 'Failed to toggle TLS status')
    } finally {
      setTogglingTls(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      if (activeTab === 'creds') {
        if (!username || !password) {
          throw new Error('Please enter both username and password')
        }
        await login(username, password)
      } else if (activeTab === 'keycloak-token') {
        if (!bearerToken.trim()) {
          throw new Error('Please enter a Keycloak JWT Bearer token')
        }
        await loginWithToken(bearerToken.trim())
      } else if (activeTab === 'mtls-cert') {
        if (!isTlsActive) {
          throw new Error('TLS authentication is deactivated. Please activate TLS or choose credentials / API key.')
        }
        if (!clientCertPem.trim()) {
          throw new Error('Please enter a client certificate Subject or PEM')
        }
        await loginWithCert(clientCertPem.trim())
      } else {
        if (!apiKey) {
          throw new Error('Please enter an API Key')
        }
        await loginWithKey(apiKey)
      }

      navigate(from, { replace: true })
    } catch (err: any) {
      setError(
        err?.response?.data?.message ||
        err?.message ||
        'Authentication failed. Please verify credentials.'
      )
    } finally {
      setLoading(false)
    }
  }

  const fillDefaultCreds = () => {
    setActiveTab('creds')
    setUsername('admin')
    setPassword('changeme')
    setError(null)
  }

  const fillDefaultKey = () => {
    setActiveTab('key')
    setApiKey('incert-admin-secret-key')
    setError(null)
  }

  return (
    <Box
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--mantine-color-dark-8)',
        backgroundImage: 'radial-gradient(circle at 50% 25%, rgba(99, 102, 241, 0.12) 0%, transparent 60%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
      }}
    >
      <Container size={500} style={{ width: '100%' }}>
        <Stack align="center" gap="xs" mb="lg">
          <ThemeIcon
            size={56}
            radius="xl"
            variant="gradient"
            gradient={isKeycloak ? { from: 'orange.6', to: 'red.6' } : { from: 'indigo.6', to: 'violet.6' }}
            style={{ boxShadow: isKeycloak ? '0 8px 24px rgba(249, 115, 22, 0.35)' : '0 8px 24px rgba(99, 102, 241, 0.35)' }}
          >
            {isKeycloak ? <IconBrandOauth size={30} stroke={1.8} /> : <IconShieldLock size={30} stroke={1.8} />}
          </ThemeIcon>

          <Title order={2} fw={800} c="white" ta="center">
            Incert OCSP Console
          </Title>
          <Text c="dimmed" size="sm" ta="center">
            Sign in to access the Admin API & PKI Operations
          </Text>

          {/* Authentication Mode Status Indicator */}
          <Group gap="xs" mt={4}>
            <Badge
              variant="dot"
              color={isKeycloak ? 'orange' : 'teal'}
              size="md"
            >
              Auth Mode: {authConfig?.authMode || 'KEYCLOCK'}
            </Badge>
            <Badge
              variant="dot"
              color={isTlsActive ? 'teal' : 'gray'}
              size="md"
            >
              TLS: {isTlsActive ? 'Active' : 'Deactivated'}
            </Badge>
            {isKeycloak && authConfig?.keycloak?.realm && (
              <Badge variant="outline" color="orange" size="xs">
                Realm: {authConfig.keycloak.realm}
              </Badge>
            )}
          </Group>
        </Stack>

        <Paper
          withBorder
          shadow="xl"
          p="xl"
          radius="lg"
          style={{
            backgroundColor: 'var(--mantine-color-dark-7)',
            borderColor: 'var(--mantine-color-dark-4)',
          }}
        >
          {error && (
            <Alert
              icon={<IconAlertCircle size={18} />}
              title="Access Denied"
              color="red"
              variant="light"
              mb="md"
              radius="md"
            >
              {error}
            </Alert>
          )}

          <Tabs value={activeTab} onChange={setActiveTab} mb="md">
            <Tabs.List grow>
              {isKeycloak ? (
                <>
                  <Tabs.Tab value="keycloak-sso" leftSection={<IconBrandOauth size={16} />}>
                    Keycloak SSO
                  </Tabs.Tab>
                  <Tabs.Tab value="keycloak-token" leftSection={<IconKey size={16} />}>
                    JWT Token
                  </Tabs.Tab>
                  <Tabs.Tab value="key" leftSection={<IconLock size={16} />}>
                    API Key
                  </Tabs.Tab>
                  <Tabs.Tab value="mtls-cert" leftSection={<IconShieldLock size={16} />}>
                    mTLS Cert
                  </Tabs.Tab>
                </>
              ) : (
                <>
                  <Tabs.Tab value="creds" leftSection={<IconUser size={16} />}>
                    Credentials
                  </Tabs.Tab>
                  <Tabs.Tab value="key" leftSection={<IconKey size={16} />}>
                    API Key
                  </Tabs.Tab>
                  <Tabs.Tab value="mtls-cert" leftSection={<IconShieldLock size={16} />}>
                    mTLS Cert
                  </Tabs.Tab>
                </>
              )}
            </Tabs.List>

            {/* KEYCLOAK SSO REDIRECT PANEL */}
            {isKeycloak && (
              <Tabs.Panel value="keycloak-sso" pt="md">
                <Stack gap="md">
                  <Box
                    p="md"
                    style={{
                      backgroundColor: 'rgba(249, 115, 22, 0.08)',
                      border: '1px solid rgba(249, 115, 22, 0.25)',
                      borderRadius: 8,
                    }}
                  >
                    <Group gap="xs" mb="xs">
                      <ThemeIcon size="sm" color="orange" variant="light">
                        <IconBrandOauth size={14} />
                      </ThemeIcon>
                      <Text size="sm" fw={700} c="orange.3">
                        Keycloak Single Sign-On Active
                      </Text>
                    </Group>
                    <Text size="xs" c="dimmed">
                      You will be redirected to the Incert Keycloak identity server to authenticate your credentials and group memberships.
                    </Text>
                  </Box>

                  <Button
                    fullWidth
                    size="lg"
                    radius="md"
                    loading={loading}
                    variant="gradient"
                    gradient={{ from: 'orange.6', to: 'red.6' }}
                    leftSection={<IconBrandOauth size={22} />}
                    rightSection={<IconArrowRight size={18} />}
                    onClick={redirectToKeycloak}
                  >
                    Sign In with Keycloak
                  </Button>

                  <Divider label="Keycloak Configured Users & Groups" labelPosition="center" />

                  <Stack gap={6}>
                    <Group justify="space-between">
                      <Group gap={6}>
                        <IconUsersGroup size={14} color="#f97316" />
                        <Text size="xs" fw={600} c="gray.3">ocsp-administrators</Text>
                      </Group>
                      <Text size="xs" c="dimmed">User: <Code color="orange">admin / changeme</Code></Text>
                    </Group>

                    <Group justify="space-between">
                      <Group gap={6}>
                        <IconUsersGroup size={14} color="#38bdf8" />
                        <Text size="xs" fw={600} c="gray.3">ocsp-operators</Text>
                      </Group>
                      <Text size="xs" c="dimmed">User: <Code color="cyan">operator / changeme</Code></Text>
                    </Group>

                    <Group justify="space-between">
                      <Group gap={6}>
                        <IconUsersGroup size={14} color="#a855f7" />
                        <Text size="xs" fw={600} c="gray.3">ocsp-auditors</Text>
                      </Group>
                      <Text size="xs" c="dimmed">User: <Code color="violet">auditor / changeme</Code></Text>
                    </Group>
                  </Stack>
                </Stack>
              </Tabs.Panel>
            )}

            {/* MANUAL TOKEN PANEL (KEYCLOAK) */}
            {isKeycloak && (
              <Tabs.Panel value="keycloak-token" pt="md">
                <form onSubmit={handleSubmit}>
                  <Stack gap="sm">
                    <Textarea
                      label="Keycloak Bearer JWT"
                      placeholder="Paste your OAuth2 token (eyJhbGciOi...)"
                      minRows={3}
                      maxRows={5}
                      value={bearerToken}
                      onChange={(e) => setBearerToken(e.currentTarget.value)}
                      required
                    />
                    <Text size="xs" c="dimmed">
                      Verified against realm <Code color="orange">{authConfig?.keycloak?.realm || 'incert'}</Code>. Requires <Code color="indigo">ROLE_ADMIN</Code>.
                    </Text>
                    <Button
                      type="submit"
                      fullWidth
                      mt="md"
                      size="md"
                      radius="md"
                      loading={loading}
                      variant="filled"
                      color="orange"
                      rightSection={<IconArrowRight size={18} />}
                    >
                      Verify & Sign In
                    </Button>
                  </Stack>
                </form>
              </Tabs.Panel>
            )}

            {/* SELF MANAGED USERNAME/PASSWORD PANEL */}
            {!isKeycloak && (
              <Tabs.Panel value="creds" pt="md">
                <form onSubmit={handleSubmit}>
                  <Stack gap="sm">
                    <TextInput
                      label="Admin Username"
                      placeholder="admin"
                      leftSection={<IconUser size={16} />}
                      value={username}
                      onChange={(e) => setUsername(e.currentTarget.value)}
                      required
                    />

                    <PasswordInput
                      label="Admin Password"
                      placeholder="Your password"
                      leftSection={<IconLock size={16} />}
                      value={password}
                      onChange={(e) => setPassword(e.currentTarget.value)}
                      required
                    />

                    <Button
                      type="submit"
                      fullWidth
                      mt="md"
                      size="md"
                      radius="md"
                      loading={loading}
                      variant="gradient"
                      gradient={{ from: 'indigo.6', to: 'violet.6' }}
                      rightSection={<IconArrowRight size={18} />}
                    >
                      Sign In to Admin Console
                    </Button>
                  </Stack>
                </form>
              </Tabs.Panel>
            )}

            {/* API KEY PANEL (BOTH MODES) */}
            <Tabs.Panel value="key" pt="md">
              <form onSubmit={handleSubmit}>
                <Stack gap="sm">
                  <PasswordInput
                    label="X-API-KEY Header"
                    placeholder="incert-admin-secret-key"
                    leftSection={<IconKey size={16} />}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.currentTarget.value)}
                    required
                  />
                  <Text size="xs" c="dimmed">
                    Direct administrative access to all <code>/api/v1/admin/**</code> endpoints (supported across both SELF_MANAGED and KEYCLOCK modes).
                  </Text>
                  <Button
                    type="submit"
                    fullWidth
                    mt="md"
                    size="md"
                    radius="md"
                    loading={loading}
                    variant="filled"
                    color="gray"
                    rightSection={<IconArrowRight size={18} />}
                  >
                    Authenticate with API Key
                  </Button>
                </Stack>
              </form>
            </Tabs.Panel>

            {/* mTLS CLIENT CERTIFICATE PANEL */}
            <Tabs.Panel value="mtls-cert" pt="md">
              <form onSubmit={handleSubmit}>
                <Stack gap="sm">
                  {!isTlsActive ? (
                    <Alert
                      icon={<IconAlertCircle size={18} />}
                      title="TLS Authentication Deactivated"
                      color="gray"
                      variant="light"
                      radius="md"
                    >
                      <Text size="sm">
                        TLS / mTLS authentication is currently <strong>deactivated</strong> in the OCSP responder configuration (<code>security.tls.enabled = false</code>).
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        Client certificate authentication cannot be used while TLS is deactivated. You can activate TLS below or use credentials / API key.
                      </Text>
                      <Button
                        size="xs"
                        variant="light"
                        color="teal"
                        mt="sm"
                        onClick={handleToggleTls}
                        loading={togglingTls}
                      >
                        Activate TLS Now
                      </Button>
                    </Alert>
                  ) : (
                    <>
                      <Alert
                        icon={<IconShieldLock size={18} />}
                        title="mTLS Transport Security Active"
                        color="teal"
                        variant="light"
                        radius="md"
                      >
                        <Text size="sm">
                          Mutual TLS is active. The OCSP Responder accepts verified client certificates (e.g. Incert Admin or RabbitMQ Client Certificate) for secure login.
                        </Text>
                      </Alert>

                      <TextInput
                        label="Client Certificate Subject / Identity"
                        placeholder="CN=admin,O=Incert Certificate Authority,C=LU"
                        leftSection={<IconShieldLock size={16} />}
                        value={clientCertPem}
                        onChange={(e) => setClientCertPem(e.currentTarget.value)}
                        required
                      />

                      <Button
                        type="submit"
                        fullWidth
                        mt="md"
                        size="md"
                        radius="md"
                        loading={loading}
                        variant="gradient"
                        gradient={{ from: 'teal.6', to: 'cyan.6' }}
                        rightSection={<IconArrowRight size={18} />}
                      >
                        Sign In via mTLS Certificate
                      </Button>
                    </>
                  )}
                </Stack>
              </form>
            </Tabs.Panel>
          </Tabs>

          <Box
            p="xs"
            mt="md"
            style={{
              backgroundColor: 'rgba(99, 102, 241, 0.06)',
              border: '1px dashed rgba(99, 102, 241, 0.25)',
              borderRadius: 8,
            }}
          >
            <Group justify="space-between" mb={6}>
              <Text size="xs" fw={700} c="dimmed" tt="uppercase">
                Authentication & Security Settings
              </Text>
              <Group gap="xs">
                <Badge size="xs" variant="light" color={isKeycloak ? 'orange' : 'indigo'}>
                  {authConfig?.authMode || 'KEYCLOCK'}
                </Badge>
                <Badge size="xs" variant="light" color={isTlsActive ? 'teal' : 'gray'}>
                  TLS {isTlsActive ? 'ACTIVE' : 'DEACTIVATED'}
                </Badge>
              </Group>
            </Group>

            <Stack gap={4}>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  TLS Security: <Code color={isTlsActive ? 'teal' : 'gray'}>{isTlsActive ? 'Active (Strict Transport)' : 'Deactivated'}</Code>
                </Text>
                <Button
                  variant="subtle"
                  size="compact-xs"
                  color={isTlsActive ? 'red' : 'teal'}
                  onClick={handleToggleTls}
                  loading={togglingTls}
                >
                  {isTlsActive ? 'Deactivate TLS' : 'Activate TLS'}
                </Button>
              </Group>

              {!isKeycloak && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">
                    User: <Code color="indigo">admin / changeme</Code>
                  </Text>
                  <Button variant="subtle" size="compact-xs" color="indigo" onClick={fillDefaultCreds}>
                    Autofill
                  </Button>
                </Group>
              )}

              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  API Key: <Code color="indigo">incert-admin-secret-key</Code>
                </Text>
                <Button variant="subtle" size="compact-xs" color="indigo" onClick={fillDefaultKey}>
                  Autofill
                </Button>
              </Group>

              {isKeycloak && authConfig?.keycloak && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">
                    Server: <Code color="orange">{authConfig.keycloak.authServerUrl}</Code>
                  </Text>
                  <Button
                    component="a"
                    href={`${authConfig.keycloak.authServerUrl}/realms/${authConfig.keycloak.realm}/account`}
                    target="_blank"
                    rel="noreferrer"
                    variant="subtle"
                    size="compact-xs"
                    color="orange"
                    leftSection={<IconExternalLink size={12} />}
                  >
                    Keycloak Console
                  </Button>
                </Group>
              )}
            </Stack>
          </Box>
        </Paper>

        <Text size="xs" c="dimmed" ta="center" mt="md">
          RFC 6960 OCSP Responder • Incert Certificate Authority
        </Text>
      </Container>
    </Box>
  )
}
