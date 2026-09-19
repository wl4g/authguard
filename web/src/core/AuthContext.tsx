import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { browserSession, logout, type LoginResponse } from './api'

type AuthValue = {
  authentication: LoginResponse | null
  ready: boolean
  accept: (result: LoginResponse) => void
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  // Browser authentication is delivered in the HttpOnly authguard_token
  // cookie. Keep only display state in memory; never persist a JWT in Web
  // storage or share it between SPAs.
  const [authentication, setAuthentication] = useState<LoginResponse | null>(null)
  const [ready, setReady] = useState(false)
  useEffect(() => {
    browserSession()
      .then(({ principal }) => setAuthentication({ accessToken: '', tokenType: 'Bearer', expiresIn: 0, returnUri: '', principal }))
      .catch(() => undefined)
      .finally(() => setReady(true))
  }, [])
  const value = useMemo<AuthValue>(() => ({
    authentication,
    ready,
    accept(result) { setAuthentication(result) },
    async signOut() {
      try { await logout() }
      finally { setAuthentication(null) }
    },
  }), [authentication, ready])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('AuthProvider is missing')
  return value
}
