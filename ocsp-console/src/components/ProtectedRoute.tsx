import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { Center, Loader, Stack, Text } from '@mantine/core'
import { useAuth } from '../context/AuthContext'

export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <Center style={{ height: '100vh', backgroundColor: 'var(--mantine-color-dark-7)' }}>
        <Stack align="center" gap="sm">
          <Loader color="indigo" size="md" />
          <Text size="sm" c="dimmed">Verifying session...</Text>
        </Stack>
      </Center>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }

  return <>{children}</>
}

