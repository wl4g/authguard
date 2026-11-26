import { useSyncExternalStore as authguard_use_sync_external_store } from 'react'
import { authguard_is_locale, type authguard_locale } from './authguard_locales'
import type { Theme as authguard_theme } from './theme'

const authguard_listeners = new Set<() => void>()
let authguard_settings: { locale?: authguard_locale; theme?: authguard_theme } = {}

function authguard_subscribe(authguard_listener: () => void) {
  authguard_listeners.add(authguard_listener)
  return () => { authguard_listeners.delete(authguard_listener) }
}

/** Synchronizes mounted remotes and remembers preferences for later mounts. Never changes host DOM. */
export function authguard_set_locale(authguard_value: authguard_locale) {
  if (!authguard_is_locale(authguard_value)) throw new Error('Unsupported AuthGuard locale')
  authguard_settings = { ...authguard_settings, locale: authguard_value }
  authguard_listeners.forEach(authguard_listener => authguard_listener())
}

export function authguard_set_theme(authguard_value: authguard_theme) {
  if (!['dark', 'light', 'system'].includes(authguard_value)) throw new Error('Unsupported AuthGuard theme')
  authguard_settings = { ...authguard_settings, theme: authguard_value }
  authguard_listeners.forEach(authguard_listener => authguard_listener())
}

export function authguard_use_settings() {
  return authguard_use_sync_external_store(authguard_subscribe, () => authguard_settings, () => authguard_settings)
}
