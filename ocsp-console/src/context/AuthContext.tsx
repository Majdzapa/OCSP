import React, { createContext, useContext, useState, useEffect } from 'react'
import type { AuthUser, AuthConfig } from '../types/api'
import {
  loginWithCredentials,
  loginWithApiKey,
  loginWithBearerToken,
  exchangeKeycloakCredentials,
  getAuthMe,
  getAuthConfig,
} from '../api/client'

interface AuthContextType {
  user: AuthUser | null
  authConfig: AuthConfig | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  loginWithKey: (apiKey: string) => Promise<void>
  loginWithToken: (token: string) => Promise<void>
  loginWithKeycloakCredentials: (username: string, password: string) => Promise<void>
  logout: () => void
  refreshAuthConfig: () => Promise<AuthConfig | null>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [authConfig, setAuthConfig] = useState<AuthConfig | null>(null)
  const [user, setUser] = useState<AuthUser | null>(() => {
    const savedUser = localStorage.getItem('ocsp_auth_user')
    const hasToken = localStorage.getItem('ocsp_bearer_token')
    const hasKey = localStorage.getItem('ocsp_api_key')
    const hasBasic = localStorage.getItem('ocsp_basic_auth')
    if (savedUser && (hasToken || hasKey || hasBasic)) {
      return {
        authenticated: true,
        username: savedUser,
        token: hasToken || undefined,
        apiKey: hasKey || undefined,
        basicAuth: hasBasic || undefined,
      }
    }
    return null
  })

  const [isLoading, setIsLoading] = useState<boolean>(true)

  const logout = () => {
    localStorage.removeItem('ocsp_auth_user')
    localStorage.removeItem('ocsp_api_key')
    localStorage.removeItem('ocsp_basic_auth')
    localStorage.removeItem('ocsp_bearer_token')
    setUser(null)
  }

  const refreshAuthConfig = async (): Promise<AuthConfig | null> => {
    try {
      const cfg = await getAuthConfig()
      setAuthConfig(cfg)
      return cfg
    } catch (e) {
      console.warn('Failed to fetch auth configuration from responder:', e)
      return null
    }
  }

  // Validate existing stored token on mount & fetch server auth config
  useEffect(() => {
    const initAuth = async () => {
      await refreshAuthConfig()

      const hasToken = localStorage.getItem('ocsp_bearer_token')
      const hasKey = localStorage.getItem('ocsp_api_key')
      const hasBasic = localStorage.getItem('ocsp_basic_auth')
      if (!hasToken && !hasKey && !hasBasic) {
        setIsLoading(false)
        return
      }

      try {
        const info = await getAuthMe()
        if (info.authenticated) {
          setUser({
            authenticated: true,
            username: info.username,
            roles: info.roles,
            authMode: info.authMode,
            token: hasToken || undefined,
            apiKey: hasKey || undefined,
            basicAuth: hasBasic || undefined,
          })
        } else {
          logout()
        }
      } catch (err) {
        logout()
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()

    const handleUnauthorized = () => {
      logout()
    }
    window.addEventListener('ocsp:unauthorized', handleUnauthorized)
    return () => window.removeEventListener('ocsp:unauthorized', handleUnauthorized)
  }, [])

  const login = async (username: string, password: string) => {
    const res = await loginWithCredentials(username, password)
    if (!res.authenticated) {
      throw new Error(res.message || 'Invalid credentials')
    }

    if (res.basicAuth) localStorage.setItem('ocsp_basic_auth', res.basicAuth)
    if (res.apiKey) localStorage.setItem('ocsp_api_key', res.apiKey)
    localStorage.setItem('ocsp_auth_user', res.username || username)

    setUser({
      authenticated: true,
      username: res.username || username,
      roles: res.roles,
      authMode: res.authMode,
      basicAuth: res.basicAuth,
      apiKey: res.apiKey,
    })
  }

  const loginWithKey = async (apiKey: string) => {
    const res = await loginWithApiKey(apiKey)
    if (!res.authenticated) {
      throw new Error(res.message || 'Invalid API Key')
    }

    localStorage.setItem('ocsp_api_key', res.apiKey || apiKey)
    localStorage.setItem('ocsp_auth_user', res.username || 'api-key-admin')

    setUser({
      authenticated: true,
      username: res.username || 'api-key-admin',
      roles: res.roles,
      authMode: res.authMode,
      apiKey: res.apiKey || apiKey,
    })
  }

  const loginWithToken = async (token: string) => {
    const res = await loginWithBearerToken(token)
    if (!res.authenticated) {
      throw new Error(res.message || 'Invalid Bearer token')
    }

    localStorage.setItem('ocsp_bearer_token', token)
    localStorage.setItem('ocsp_auth_user', res.username || 'keycloak-admin')

    setUser({
      authenticated: true,
      username: res.username || 'keycloak-admin',
      roles: res.roles,
      authMode: res.authMode || 'KEYCLOCK',
      token,
    })
  }

  const loginWithKeycloakCredentials = async (kcUsername: string, kcPassword: string) => {
    const serverUrl = authConfig?.keycloak?.authServerUrl || 'http://localhost:8081'
    const realm = authConfig?.keycloak?.realm || 'incert'
    const clientId = authConfig?.keycloak?.clientId || 'ocsp-console'

    const token = await exchangeKeycloakCredentials(serverUrl, realm, clientId, kcUsername, kcPassword)
    await loginWithToken(token)
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        authConfig,
        isAuthenticated: !!user?.authenticated,
        isLoading,
        login,
        loginWithKey,
        loginWithToken,
        loginWithKeycloakCredentials,
        logout,
        refreshAuthConfig,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
