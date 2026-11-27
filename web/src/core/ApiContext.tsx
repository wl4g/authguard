import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'

type ApiValue = { token: string; setToken: (token: string) => void }
const ApiContext = createContext<ApiValue | null>(null)

export function ApiProvider({ children, authguard_api_token, authguard_embedded = false }: { children: ReactNode; authguard_api_token?: string; authguard_embedded?: boolean }) {
  const [token, setTokenState] = useState(() => authguard_embedded ? '' : sessionStorage.getItem('authguard.api-token') || '')
  const value = useMemo(() => ({
    token: authguard_api_token ?? token,
    setToken(next: string) { if (!authguard_embedded) sessionStorage.setItem('authguard.api-token', next); setTokenState(next) },
  }), [authguard_api_token, authguard_embedded, token])
  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>
}

export function useApi() {
  const value = useContext(ApiContext)
  if (!value) throw new Error('ApiProvider is missing')
  return value
}
