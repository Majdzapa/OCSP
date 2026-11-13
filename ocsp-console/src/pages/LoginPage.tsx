import React, { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Container,
  Paper,
  Title,
  Text,
  TextInput,
  PasswordInput,
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
} from '@tabler/icons-react'
import { useAuth } from '../context/AuthContext'

export const LoginPage: React.FC = () => {
  const { login, loginWithKey } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const [activeTab, setActiveTab] = useState<string | null>('creds')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('changeme')
  const [apiKey, setApiKey] = useState('incert-admin-secret-key')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

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
      <Container size={440} style={{ width: '100%' }}>
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
              <Tabs.Tab value="creds" leftSection={<IconUser size={16} />}>
                Credentials
              </Tabs.Tab>
              <Tabs.Tab value="key" leftSection={<IconKey size={16} />}>
                API Key
              </Tabs.Tab>
            </Tabs.List>

            <form onSubmit={handleSubmit}>
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
                    Grants direct administrative access to all <code>/api/v1/admin/**</code> endpoints.
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
                gradient={{ from: 'indigo.6', to: 'violet.6' }}
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
                Default Credentials
              </Text>
              <Badge size="xs" variant="light" color="indigo">DEV / LOCAL</Badge>
            </Group>

            <Stack gap={4}>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  User: <Code color="indigo">admin / changeme</Code>
                </Text>
                <Button variant="subtle" size="compact-xs" color="indigo" onClick={fillDefaultCreds}>
                  Autofill
                </Button>
              </Group>

              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  API Key: <Code color="indigo">incert-admin-secret-key</Code>
                </Text>
                <Button variant="subtle" size="compact-xs" color="indigo" onClick={fillDefaultKey}>
                  Autofill
                </Button>
              </Group>
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

