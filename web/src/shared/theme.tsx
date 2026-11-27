import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react'
import { authguard_use_settings } from './authguard_settings'

export type Theme = 'dark' | 'light' | 'system'
type ThemeValue = { theme: Theme; authguard_resolved_theme: 'dark' | 'light'; setTheme: (theme: Theme) => void }
const ThemeContext = createContext<ThemeValue | null>(null)
const authguard_root_context = createContext<RefObject<HTMLDivElement | null> | null>(null)

export function ThemeProvider({ children, authguard_theme }: { children: ReactNode; authguard_theme?: Theme }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    const authguard_saved = localStorage.getItem('authguard.theme')
    return authguard_saved === 'dark' || authguard_saved === 'light' ? authguard_saved : 'system'
  })
  const authguard_settings = authguard_use_settings()
  const authguard_current = authguard_theme ?? authguard_settings.theme ?? theme
  const authguard_root = useRef<HTMLDivElement>(null)
  const [authguard_dark, authguard_set_dark] = useState(() => matchMedia('(prefers-color-scheme: dark)').matches)
  useEffect(() => {
    const authguard_media = matchMedia('(prefers-color-scheme: dark)')
    const authguard_apply = () => authguard_set_dark(authguard_media.matches)
    authguard_apply(); authguard_media.addEventListener('change', authguard_apply)
    return () => authguard_media.removeEventListener('change', authguard_apply)
  }, [])
  const authguard_resolved_theme = authguard_current === 'system' ? (authguard_dark ? 'dark' : 'light') : authguard_current
  const value = useMemo(() => ({ theme: authguard_current, authguard_resolved_theme, setTheme(next: Theme) { localStorage.setItem('authguard.theme', next); setThemeState(next) } }), [authguard_current, authguard_resolved_theme])
  return <ThemeContext.Provider value={value}><authguard_root_context.Provider value={authguard_root}>
    <div ref={authguard_root} className="authguard-root" data-authguard-theme={authguard_resolved_theme}>{children}</div>
  </authguard_root_context.Provider></ThemeContext.Provider>
}

export function authguard_use_root() { return useContext(authguard_root_context) }

export function useTheme() {
  const value = useContext(ThemeContext)
  if (!value) throw new Error('ThemeProvider is missing')
  return value
}
