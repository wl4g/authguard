import { useLayoutEffect as authguard_use_layout_effect, useRef as authguard_use_ref, useState as authguard_use_state, type ReactNode as authguard_node } from 'react'
import { createPortal as authguard_create_portal } from 'react-dom'
import * as authguard_router from 'react-router-dom'
import * as authguard_auth from '../core/AuthContext'
import * as authguard_api from '../core/ApiContext'
import * as authguard_i18n from '../shared/i18n'
import * as authguard_theme from '../shared/theme'
import authguard_styles from '../shared/styles.css?inline'

export type authguard_remote_props = {
  authguard_locale?: authguard_i18n.Locale
  authguard_theme?: authguard_theme.Theme
  /** Optional, short-lived management credential supplied in memory by the host. Never hardcode service tokens. */
  authguard_api_token?: string
  authguard_on_return: () => void
}

function authguard_session({ children: authguard_children, authguard_on_return }: { children: authguard_node; authguard_on_return: () => void }) {
  const { authentication: authguard_authentication, ready: authguard_ready } = authguard_auth.useAuth()
  const { t: authguard_t } = authguard_i18n.useI18n()
  if (!authguard_ready) return <div className="authguard-loading" role="status">{authguard_t('connecting')}</div>
  if (!authguard_authentication) return <div><a className="authguard-sign-in" href={`/auth/login?return_to=${encodeURIComponent(location.pathname + location.search)}`}>{authguard_t('authguard_sign_in')}</a><button className="authguard-return" data-testid="authguard-return" onClick={authguard_on_return}>{authguard_t('authguard_back')}</button></div>
  return authguard_children
}
const authguard_components = { session: authguard_session }

/** Each mount owns its styles, providers and router; no host header or document effects. */
export function authguard_boundary({ children: authguard_children, ...authguard_props }: authguard_remote_props & { children: authguard_node }) {
  const authguard_host = authguard_use_ref<HTMLDivElement>(null)
  const [authguard_shadow, authguard_set_shadow] = authguard_use_state<ShadowRoot | null>(null)
  authguard_use_layout_effect(() => {
    if (authguard_host.current) authguard_set_shadow(authguard_host.current.shadowRoot || authguard_host.current.attachShadow({ mode: 'open' }))
  }, [])
  return <div className="authguard-remote-host" ref={authguard_host}>{authguard_shadow && authguard_create_portal(<>
    <style>{authguard_styles}</style>
    <authguard_theme.ThemeProvider authguard_theme={authguard_props.authguard_theme}>
      <authguard_i18n.I18nProvider authguard_locale={authguard_props.authguard_locale}>
        <authguard_auth.AuthProvider><authguard_api.ApiProvider authguard_embedded authguard_api_token={authguard_props.authguard_api_token}>
          <authguard_router.MemoryRouter><authguard_components.session authguard_on_return={authguard_props.authguard_on_return}>{authguard_children}</authguard_components.session></authguard_router.MemoryRouter>
        </authguard_api.ApiProvider></authguard_auth.AuthProvider>
      </authguard_i18n.I18nProvider>
    </authguard_theme.ThemeProvider>
  </>, authguard_shadow)}</div>
}
