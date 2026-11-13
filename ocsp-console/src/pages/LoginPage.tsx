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
} from '@tabler/icons-react'
import { useAuth } from '../context/AuthContext'

export const LoginPage: React.FC = () => {
  const { login, loginWithKey, loginWithToken, authConfig } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const isKeycloak = !!authConfig?.isKeycloak
  const [activeTab, setActiveTab] = useState<string | null>(isKeycloak ? 'keycloak' : 'creds')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('changeme')
  const [apiKey, setApiKey] = useState('incert-admin-secret-key')
  const [bearerToken, setBearerToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  // Switch default tab if authConfig loads after initial render
  useEffect(() => {
    if (authConfig?.isKeycloak && activeTab === 'creds') {
      setActiveTab('keycloak')
    }
  }, [authConfig?.isKeycloak])

  const from = (location.state as any)?.from?.pathname || '/dashboard'

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
      } else if (activeTab === 'keycloak') {
        if (!bearerToken.trim()) {
          throw new Error('Please enter a Keycloak JWT Bearer token')
        }
        await loginWithToken(bearerToken.trim())
      } else {
        if (!apiKey) {
          throw new Error('Please enter an API Key')
        }
        await loginWithKey(apiKey)
      }

      navigate(from, { replace: true })
    } catch (err: any) {
      setError(err?.response?.data?.message || err?.message || 'Authentication failed. Please verify credentials.')
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
      <Container size={460} style={{ width: '100%' }}>
        <Stack align="center" gap="xs" mb="lg">
          <ThemeIcon
            size={56}
            radius="xl"
            variant="gradient"
            gradient={{ from: 'indigo.6', to: 'violet.6' }}
            style={{ boxShadow: '0 8px 24px rgba(99, 102, 241, 0.35)' }}
          >
            <IconShieldLock size={30} stroke={1.8} />
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
              Auth Mode: {authConfig?.authMode || 'SELF_MANAGED'}
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
              {!isKeycloak && (
                <Tabs.Tab value="creds" leftSection={<IconUser size={16} />}>
                  Credentials
                </Tabs.Tab>
              )}
              {isKeycloak && (
                <Tabs.Tab value="keycloak" leftSection={<IconBrandOauth size={16} />}>
                  Keycloak JWT
                </Tabs.Tab>
              )}
              <Tabs.Tab value="key" leftSection={<IconKey size={16} />}>
                API Key
              </Tabs.Tab>
            </Tabs.List>

            <form onSubmit={handleSubmit}>
              {!isKeycloak && (
                <Tabs.Panel value="creds" pt="md">
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
                  </Stack>
                </Tabs.Panel>
              )}

              {isKeycloak && (
                <Tabs.Panel value="keycloak" pt="md">
                  <Stack gap="sm">
                    <Textarea
                      label="Keycloak JWT Bearer Token"
                      placeholder="Paste your OAuth2 / OIDC access token (eyJhbGciOi...)"
                      minRows={3}
                      maxRows={5}
                      value={bearerToken}
                      onChange={(e) => setBearerToken(e.currentTarget.value)}
                      required
                    />
                    <Text size="xs" c="dimmed">
                      Verified against Keycloak realm <Code color="orange">{authConfig?.keycloak?.realm || 'incert'}</Code>. Requires <Code color="indigo">ROLE_ADMIN</Code>.
                    </Text>
                    {authConfig?.keycloak?.authServerUrl && (
                      <Group justify="flex-start" gap="xs">
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
                          Open Keycloak Account Console
                        </Button>
                      </Group>
                    )}
                  </Stack>
                </Tabs.Panel>
              )}

              <Tabs.Panel value="key" pt="md">
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
                    Grants direct administrative access to all <code>/api/v1/admin/**</code> endpoints (supported in both SELF_MANAGED and KEYCLOCK modes).
                  </Text>
                </Stack>
              </Tabs.Panel>

              <Button
                type="submit"
                fullWidth
                mt="xl"
                size="md"
                radius="md"
                loading={loading}
                variant="gradient"
                gradient={isKeycloak ? { from: 'orange.6', to: 'red.6' } : { from: 'indigo.6', to: 'violet.6' }}
                rightSection={<IconArrowRight size={18} />}
              >
                Sign In to Admin Console
              </Button>
            </form>
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
                Authentication Settings
              </Text>
              <Badge size="xs" variant="light" color={isKeycloak ? 'orange' : 'indigo'}>
                {authConfig?.authMode || 'SELF_MANAGED'}
              </Badge>
            </Group>

            <Stack gap={4}>
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
                <Text size="xs" c="dimmed">
                  Server: <Code color="orange">{authConfig.keycloak.authServerUrl}</Code>
                </Text>
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
