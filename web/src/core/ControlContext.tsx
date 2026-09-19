import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'

type ControlValue = { token: string; setToken: (token: string) => void }
const ControlContext = createContext<ControlValue | null>(null)

export function ControlProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState(() => sessionStorage.getItem('authguard.control-token') || '')
  const value = useMemo(() => ({
    token,
    setToken(next: string) { sessionStorage.setItem('authguard.control-token', next); setTokenState(next) },
  }), [token])
  return <ControlContext.Provider value={value}>{children}</ControlContext.Provider>
}

export function useControl() {
  const value = useContext(ControlContext)
  if (!value) throw new Error('ControlProvider is missing')
  return value
}
