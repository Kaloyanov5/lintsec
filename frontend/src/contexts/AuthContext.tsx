import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from '@/lib/api'
import type { UserDto } from '@/types'

export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'

type AuthContextValue = {
  user: UserDto | null
  status: AuthStatus
  setUser: (user: UserDto | null) => void
  refresh: () => Promise<void>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUserState] = useState<UserDto | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')

  const refresh = async () => {
    try {
      const { data } = await api.get<UserDto>('/me')
      setUserState(data)
      setStatus('authenticated')
    } catch {
      setUserState(null)
      setStatus('unauthenticated')
    }
  }

  const signOut = async () => {
    try {
      await api.post('/auth/logout')
    } finally {
      setUserState(null)
      setStatus('unauthenticated')
    }
  }

  const setUser = (next: UserDto | null) => {
    setUserState(next)
    setStatus(next ? 'authenticated' : 'unauthenticated')
  }

  useEffect(() => {
    refresh()
  }, [])

  return (
    <AuthContext.Provider value={{ user, status, setUser, refresh, signOut }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}
