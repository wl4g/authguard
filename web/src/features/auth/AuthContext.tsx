import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'
import type { LoginResponse } from '../../lib/api'

type AuthValue = {
  authentication: LoginResponse | null
  accept: (result: LoginResponse) => void
  signOut: () => void
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authentication, setAuthentication] = useState<LoginResponse | null>(() => {
    try { return JSON.parse(localStorage.getItem('authguard.authentication') || 'null') as LoginResponse | null }
    catch { return null }
  })
  const value = useMemo<AuthValue>(() => ({
    authentication,
    accept(result) { localStorage.setItem('authguard.authentication', JSON.stringify(result)); setAuthentication(result) },
    signOut() { localStorage.removeItem('authguard.authentication'); setAuthentication(null) },
  }), [authentication])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('AuthProvider is missing')
  return value
}
