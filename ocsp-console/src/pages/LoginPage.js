import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Container, Paper, Title, Text, TextInput, PasswordInput, Button, Alert, Group, Stack, ThemeIcon, Badge, Box, Divider, } from '@mantine/core';
import { IconLock, IconUser, IconShieldLock, IconAlertCircle, IconArrowRight, IconBrandOauth, IconCertificate, IconBolt, } from '@tabler/icons-react';
import { useAuth } from '../context/AuthContext';
/**
 * Login page. The flow is dictated by how the responder is deployed:
 *  - mTLS enabled       -> tries/offers browser client certificate auth, falling back to mode login
 *  - KEYCLOAK mode      -> redirect to the Keycloak login page
 *  - SELF_MANAGEMENT    -> username / password form (issues Bearer JWT)
 */
export const LoginPage = () => {
    const { login, loginWithToken, loginWithClientCert, authConfig } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();
    const isKeycloak = !!authConfig?.isKeycloak;
    const isTlsActive = authConfig?.tlsEnabled !== false;
    const isMtlsEnabled = !!authConfig?.clientCertAuthEnabled;
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [mtlsInfo, setMtlsInfo] = useState(null);
    const [loading, setLoading] = useState(false);
    const [mtlsLoading, setMtlsLoading] = useState(false);
    const from = location.state?.from?.pathname ?? '/dashboard';

    // When mTLS is enabled, silently probe if the browser presented a trusted, user-linked certificate.
    useEffect(() => {
        if (!isMtlsEnabled) return;
        let cancelled = false;
        setMtlsLoading(true);
        loginWithClientCert()
            .then(() => {
                if (!cancelled) navigate(from, { replace: true });
            })
            .catch(() => {
                if (!cancelled) {
                    setMtlsInfo('No linked client certificate detected. Choose a certificate or sign in below.');
                }
            })
            .finally(() => {
                if (!cancelled) setMtlsLoading(false);
            });
        return () => { cancelled = true; };
    }, [isMtlsEnabled]);

    const handleMtlsLogin = async () => {
        setError(null);
        setMtlsInfo(null);
        setMtlsLoading(true);
        try {
            await loginWithClientCert();
            navigate(from, { replace: true });
        } catch (err) {
            const msg = err?.response?.data?.message || (err instanceof Error ? err.message : 'Client certificate authentication failed');
            setMtlsInfo(msg);
        } finally {
            setMtlsLoading(false);
        }
    };
    // Handle the redirect back from Keycloak: the token arrives in the URL fragment.
    useEffect(() => {
        const hash = window.location.hash;
        if (!hash.includes('access_token='))
            return;
        const params = new URLSearchParams(hash.replace(/^#/, ''));
        const token = params.get('access_token');
        const idToken = params.get('id_token');
        if (!token)
            return;
        setLoading(true);
        loginWithToken(token, idToken)
            .then(() => {
            // Remove the token from the address bar.
            window.history.replaceState(null, '', window.location.pathname);
            navigate(from, { replace: true });
        })
            .catch((err) => {
            setError(err instanceof Error ? err.message : 'Keycloak authentication failed');
            setLoading(false);
        });
    }, [location.hash, loginWithToken, navigate, from]);
    const redirectToKeycloak = () => {
        const kc = authConfig?.keycloak;
        if (!kc?.authServerUrl || !kc.realm || !kc.clientId) {
            setError('Keycloak configuration is not available. Check server auth config.');
            return;
        }
        const consoleBase = (import.meta.env.BASE_URL || '/console/').replace(/\/$/, '');
        const redirectUri = encodeURIComponent(`${window.location.origin}${consoleBase}/login`);
        window.location.href =
            `${kc.authServerUrl}/realms/${kc.realm}/protocol/openid-connect/auth` +
                `?client_id=${kc.clientId}&redirect_uri=${redirectUri}&response_type=token&scope=openid%20profile%20email`;
    };
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        try {
            await login(username, password);
            navigate(from, { replace: true });
        }
        catch (err) {
            const axiosMsg = err?.response?.data?.message;
            setError(axiosMsg ?? (err instanceof Error ? err.message : 'Authentication failed'));
        }
        finally {
            setLoading(false);
        }
    };
    return (<Box style={{
            minHeight: '100vh',
            backgroundColor: 'var(--mantine-color-dark-8)',
            backgroundImage: 'radial-gradient(circle at 50% 25%, rgba(99, 102, 241, 0.12) 0%, transparent 60%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '24px',
        }}>
      <Container size={440} style={{ width: '100%' }}>
        <Stack align="center" gap="xs" mb="lg">
          <ThemeIcon size={56} radius="xl" variant="gradient" gradient={isKeycloak ? { from: 'orange.6', to: 'red.6' } : { from: 'indigo.6', to: 'violet.6' }}>
            {isKeycloak ? <IconBrandOauth size={30} stroke={1.8}/> : <IconShieldLock size={30} stroke={1.8}/>}
          </ThemeIcon>
          <Title order={2} fw={800} c="white" ta="center">
            OCSP Admin Console
          </Title>
          <Text c="dimmed" size="sm" ta="center">
            Sign in to continue
          </Text>
          <Group gap="xs" mt={4}>
            <Badge variant="dot" color={isTlsActive ? 'teal' : 'gray'} size="md">
              {isTlsActive ? 'Secure connection (TLS)' : 'TLS not enabled'}
            </Badge>
            {isMtlsEnabled && (
              <Badge variant="light" color="teal" size="md">
                mTLS Client Cert Enabled
              </Badge>
            )}
          </Group>
        </Stack>

        <Paper withBorder shadow="xl" p="xl" radius="lg" style={{ backgroundColor: 'var(--mantine-color-dark-7)', borderColor: 'var(--mantine-color-dark-4)' }}>
          {error && (<Alert icon={<IconAlertCircle size={18}/>} title="Access Denied" color="red" variant="light" mb="md" radius="md">
              {error}
            </Alert>)}

          {isMtlsEnabled && (
            <Stack gap="sm" mb="md">
              {mtlsInfo && (
                <Alert icon={<IconCertificate size={18}/>} title="Client Certificate (mTLS)" color="teal" variant="light" radius="md">
                  {mtlsInfo}
                </Alert>
              )}
              <Button fullWidth size="md" radius="md" loading={mtlsLoading} variant="gradient" gradient={{ from: 'teal.6', to: 'cyan.6' }} leftSection={<IconCertificate size={20}/>} rightSection={<IconArrowRight size={16}/>} onClick={handleMtlsLogin}>
                Sign in with Browser Certificate (mTLS)
              </Button>
              <Divider label={isKeycloak ? 'or continue with Keycloak' : 'or sign in with username & password'} labelPosition="center" my="xs" />
            </Stack>
          )}

          {isKeycloak ? (<Button fullWidth size="lg" radius="md" loading={loading} variant="gradient" gradient={{ from: 'orange.6', to: 'red.6' }} leftSection={<IconBrandOauth size={22}/>} rightSection={<IconArrowRight size={18}/>} onClick={redirectToKeycloak}>
              Sign in with Keycloak
            </Button>) : (<form onSubmit={handleSubmit}>
              <Stack gap="sm">
                <TextInput label="Username" leftSection={<IconUser size={16}/>} value={username} onChange={(e) => setUsername(e.currentTarget.value)} autoComplete="username" required/>
                <PasswordInput label="Password" leftSection={<IconLock size={16}/>} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="current-password" required/>
                <Button type="submit" fullWidth mt="md" size="md" radius="md" loading={loading} variant="gradient" gradient={{ from: 'indigo.6', to: 'violet.6' }} rightSection={<IconArrowRight size={18}/>}>
                  Sign In
                </Button>
              </Stack>
            </form>)}

          <Divider label="Public Tools (No Login Required)" labelPosition="center" my="lg" />

          <Button
            fullWidth
            size="sm"
            radius="md"
            variant="light"
            color="teal"
            leftSection={<IconBolt size={17} />}
            rightSection={<IconArrowRight size={15} />}
            onClick={() => navigate('/ocsp-client')}
          >
            Open Public OCSP Client Tester
          </Button>
        </Paper>

        <Text size="xs" c="dimmed" ta="center" mt="md">
          RFC 6960 OCSP Responder — PKI Administration Console
        </Text>
      </Container>
    </Box>);
};
