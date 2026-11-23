import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginWithCredentials, loginWithBearerToken, getAuthMe, getAuthConfig, clearAuthStorage, } from '../api/client';
const AuthContext = createContext(undefined);
export const AuthProvider = ({ children }) => {
    const [authConfig, setAuthConfig] = useState(null);
    const [user, setUser] = useState(() => {
        const savedUser = localStorage.getItem('ocsp_auth_user');
        const hasToken = localStorage.getItem('ocsp_bearer_token');
        if (savedUser && hasToken) {
            return {
                authenticated: true,
                username: savedUser,
                token: hasToken,
            };
        }
        return null;
    });
    const [isLoading, setIsLoading] = useState(true);
    const clearLocalAuth = () => {
        clearAuthStorage();
        if (window.location.hash && window.location.hash.includes('access_token=')) {
            window.history.replaceState(null, '', window.location.pathname + window.location.search);
        }
        setUser(null);
    };
    const logout = () => {
        const bearerToken = localStorage.getItem('ocsp_bearer_token');
        const idToken = localStorage.getItem('ocsp_id_token');
        const wasKeycloakSession = Boolean(bearerToken) && Boolean(authConfig?.isKeycloak);
        clearLocalAuth();
        if (wasKeycloakSession && authConfig?.keycloak?.authServerUrl) {
            const kc = authConfig.keycloak;
            const postLogoutRedirectUri = encodeURIComponent(`${window.location.origin}/login`);
            let logoutUrl =
                `${kc.authServerUrl}/realms/${kc.realm}/protocol/openid-connect/logout` +
                    `?client_id=${encodeURIComponent(kc.clientId)}&post_logout_redirect_uri=${postLogoutRedirectUri}`;
            if (idToken) {
                logoutUrl += `&id_token_hint=${encodeURIComponent(idToken)}`;
            }
            window.location.href = logoutUrl;
        }
    };
    const refreshAuthConfig = async () => {
        try {
            const cfg = await getAuthConfig();
            setAuthConfig(cfg);
            return cfg;
        }
        catch (e) {
            console.warn('Failed to fetch auth configuration from responder:', e);
            return null;
        }
    };
    useEffect(() => {
        const initAuth = async () => {
            await refreshAuthConfig();
            const hasToken = localStorage.getItem('ocsp_bearer_token');
            if (!hasToken) {
                setIsLoading(false);
                return;
            }
            try {
                const info = await getAuthMe();
                if (info.authenticated) {
                    setUser({
                        authenticated: true,
                        username: info.username,
                        roles: info.roles,
                        authMode: info.authMode,
                        token: hasToken,
                    });
                }
                else {
                    clearLocalAuth();
                }
            }
            catch (err) {
                clearLocalAuth();
            }
            finally {
                setIsLoading(false);
            }
        };
        initAuth();
        const handleUnauthorized = () => {
            clearLocalAuth();
        };
        window.addEventListener('ocsp:unauthorized', handleUnauthorized);
        return () => window.removeEventListener('ocsp:unauthorized', handleUnauthorized);
    }, []);
    const login = async (username, password) => {
        const res = await loginWithCredentials(username, password);
        if (!res.authenticated || !res.accessToken) {
            throw new Error(res.message || 'Invalid credentials');
        }
        localStorage.removeItem('ocsp_basic_auth');
        localStorage.setItem('ocsp_bearer_token', res.accessToken);
        localStorage.setItem('ocsp_auth_user', res.username || username);
        setUser({
            authenticated: true,
            username: res.username || username,
            roles: res.roles,
            authMode: res.authMode,
            token: res.accessToken,
        });
    };
    const loginWithToken = async (token, idToken) => {
        const res = await loginWithBearerToken(token);
        if (!res.authenticated) {
            throw new Error(res.message || 'Invalid Bearer token');
        }
        localStorage.removeItem('ocsp_basic_auth');
        localStorage.setItem('ocsp_bearer_token', token);
        if (idToken) {
            localStorage.setItem('ocsp_id_token', idToken);
        }
        localStorage.setItem('ocsp_auth_user', res.username || 'keycloak-admin');
        setUser({
            authenticated: true,
            username: res.username || 'keycloak-admin',
            roles: res.roles,
            authMode: res.authMode,
            token,
        });
    };
    return (<AuthContext.Provider value={{
            user,
            authConfig,
            isAuthenticated: !!user?.authenticated,
            isLoading,
            login,
            loginWithToken,
            logout,
            refreshAuthConfig,
        }}>
      {children}
    </AuthContext.Provider>);
};
export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
