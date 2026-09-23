import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'

type ApiValue = { token: string; setToken: (token: string) => void }
const ApiContext = createContext<ApiValue | null>(null)

export function ApiProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState(() => sessionStorage.getItem('authguard.api-token') || '')
  const value = useMemo(() => ({
    token,
    setToken(next: string) { sessionStorage.setItem('authguard.api-token', next); setTokenState(next) },
  }), [token])
  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>
}

export function useApi() {
  const value = useContext(ApiContext)
  if (!value) throw new Error('ApiProvider is missing')
  return value
}
