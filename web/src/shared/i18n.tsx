import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { authguard_use_settings } from './authguard_settings'

import { authguard_messages as messages } from './locales/authguard_messages'
import { authguard_browser_locale, authguard_is_locale, type authguard_locale } from './authguard_locales'
import { authguard_use_root } from './theme'

export type Locale = authguard_locale

export type MessageKey = keyof typeof messages.en_US

type I18nValue = { locale: Locale; setLocale: (locale: Locale) => void; t: (key: MessageKey) => string }
const I18nContext = createContext<I18nValue | null>(null)

export function I18nProvider({ children, authguard_locale }: { children: ReactNode; authguard_locale?: Locale }) {
  const [locale, setLocaleState] = useState<Locale>(() => {
    const authguard_saved = localStorage.getItem('authguard.locale')
    return authguard_is_locale(authguard_saved) ? authguard_saved : authguard_browser_locale(navigator.language)
  })
  const authguard_settings = authguard_use_settings()
  const authguard_current = authguard_locale ?? authguard_settings.locale ?? locale
  const authguard_root = authguard_use_root()
  useEffect(() => {
    if (authguard_root?.current) authguard_root.current.lang = authguard_current.replace('_', '-')
  }, [authguard_current, authguard_root])
  const value = useMemo<I18nValue>(() => ({
    locale: authguard_current,
    setLocale(next) { localStorage.setItem('authguard.locale', next); setLocaleState(next) },
    t: (key) => messages[authguard_current][key],
  }), [authguard_current])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  const value = useContext(I18nContext)
  if (!value) throw new Error('I18nProvider is missing')
  return value
}
