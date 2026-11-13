import React, { createContext, useContext, useState, useEffect } from 'react'
import type { AuthUser } from '../types/api'
import { loginWithCredentials, loginWithApiKey, getAuthMe } from '../api/client'

interface AuthContextType {
  user: AuthUser | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  loginWithKey: (apiKey: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(() => {
    const savedUser = localStorage.getItem('ocsp_auth_user')
    const hasKey = localStorage.getItem('ocsp_api_key')
    const hasBasic = localStorage.getItem('ocsp_basic_auth')
    if (savedUser && (hasKey || hasBasic)) {
      return {
        authenticated: true,
        username: savedUser,
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
    setUser(null)
  }

  // Validate existing stored token on mount
  useEffect(() => {
    const checkAuth = async () => {
      const hasKey = localStorage.getItem('ocsp_api_key')
      const hasBasic = localStorage.getItem('ocsp_basic_auth')
      if (!hasKey && !hasBasic) {
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

    checkAuth()

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
      apiKey: res.apiKey || apiKey,
    })
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user?.authenticated,
        isLoading,
        login,
        loginWithKey,
        logout,
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

