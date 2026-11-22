import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginWithCredentials, loginWithBearerToken, getAuthMe, getAuthConfig, } from '../api/client';
const AuthContext = createContext(undefined);
export const AuthProvider = ({ children }) => {
    const [authConfig, setAuthConfig] = useState(null);
    const [user, setUser] = useState(() => {
        const savedUser = localStorage.getItem('ocsp_auth_user');
        const hasToken = localStorage.getItem('ocsp_bearer_token');
        const hasBasic = localStorage.getItem('ocsp_basic_auth');
        if (savedUser && (hasToken || hasBasic)) {
            return {
                authenticated: true,
                username: savedUser,
                token: hasToken || undefined,
                basicAuth: hasBasic || undefined,
            };
        }
        return null;
    });
    const [isLoading, setIsLoading] = useState(true);
    const logout = () => {
        localStorage.removeItem('ocsp_auth_user');
        localStorage.removeItem('ocsp_basic_auth');
        localStorage.removeItem('ocsp_bearer_token');
        setUser(null);
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
    // Validate existing stored token on mount & fetch server auth config
    useEffect(() => {
        const initAuth = async () => {
            await refreshAuthConfig();
            const hasToken = localStorage.getItem('ocsp_bearer_token');
            const hasBasic = localStorage.getItem('ocsp_basic_auth');
            if (!hasToken && !hasBasic) {
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
                        token: hasToken || undefined,
                        basicAuth: hasBasic || undefined,
                    });
                }
                else {
                    logout();
                }
            }
            catch (err) {
                logout();
            }
            finally {
                setIsLoading(false);
            }
        };
        initAuth();
        const handleUnauthorized = () => {
            logout();
        };
        window.addEventListener('ocsp:unauthorized', handleUnauthorized);
        return () => window.removeEventListener('ocsp:unauthorized', handleUnauthorized);
    }, []);
    const login = async (username, password) => {
        const res = await loginWithCredentials(username, password);
        if (!res.authenticated) {
            throw new Error(res.message || 'Invalid credentials');
        }
        const encodedBasic = 'Basic ' + btoa(`${username}:${password}`);
        localStorage.setItem('ocsp_basic_auth', encodedBasic);
        localStorage.setItem('ocsp_auth_user', res.username || username);
        setUser({
            authenticated: true,
            username: res.username || username,
            roles: res.roles,
            authMode: res.authMode,
            basicAuth: encodedBasic,
        });
    };
    const loginWithToken = async (token) => {
        const res = await loginWithBearerToken(token);
        if (!res.authenticated) {
            throw new Error(res.message || 'Invalid Bearer token');
        }
        localStorage.setItem('ocsp_bearer_token', token);
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
