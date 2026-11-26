import * as authguard_icons from 'lucide-react'
import { useEffect as authguard_use_effect, useRef as authguard_use_ref, useState as authguard_use_state } from 'react'
import { useAuth as authguard_use_auth } from '../core/AuthContext'
import { useApi as authguard_use_api } from '../core/ApiContext'
import { useI18n as authguard_use_i18n } from './i18n'
import * as authguard_preferences from './Preferences'

export function authguard_profile_menu({ authguard_sign_out_id = 'sign-out', authguard_after_sign_out }: { authguard_sign_out_id?: string; authguard_after_sign_out?: () => void }) {
  const { authentication: authguard_authentication, signOut: authguard_sign_out } = authguard_use_auth()
  const { token: authguard_token, setToken: authguard_set_token } = authguard_use_api()
  const { t: authguard_t } = authguard_use_i18n()
  const [authguard_open, authguard_set_open] = authguard_use_state(false)
  const [authguard_draft, authguard_set_draft] = authguard_use_state(authguard_token)
  const authguard_root = authguard_use_ref<HTMLDivElement>(null)
  authguard_use_effect(() => {
    if (!authguard_open) return
    function authguard_dismiss(authguard_event: PointerEvent) {
      if (!authguard_root.current?.contains(authguard_event.target as Node)) authguard_set_open(false)
    }
    document.addEventListener('pointerdown', authguard_dismiss)
    return () => document.removeEventListener('pointerdown', authguard_dismiss)
  }, [authguard_open])
  return <div className="authguard-profile-menu" ref={authguard_root} onKeyDown={authguard_event => {
    if (authguard_event.key === 'Escape') {
      authguard_set_open(false)
      authguard_root.current?.querySelector<HTMLButtonElement>('button')?.focus()
    }
  }}>
    <button className="authguard-profile-trigger" data-testid="authguard-profile-trigger" aria-expanded={authguard_open} aria-controls="authguard-system-settings" onClick={() => authguard_set_open(!authguard_open)}>
      <span data-testid="authenticated-principal" title={authguard_authentication?.principal.principalId}>{authguard_authentication?.principal.principalId}</span><authguard_icons.ChevronDown size={16}/>
    </button>
    {authguard_open && <div className="authguard-profile-dropdown" id="authguard-system-settings" role="region" aria-label={authguard_t('authguard_settings')}>
      <b>{authguard_t('authguard_settings')}</b><authguard_preferences.Preferences/>
      <form className="authguard-api-settings" onSubmit={authguard_event => { authguard_event.preventDefault(); authguard_set_token(authguard_draft) }}>
        <label>{authguard_t('apiToken')}<input data-testid="api-token" type="password" autoComplete="off" value={authguard_draft} onChange={authguard_event => authguard_set_draft(authguard_event.target.value)}/></label>
        <button data-testid="api-token-submit" type="submit">{authguard_t('saveToken')}</button>
      </form>
      <button data-testid={authguard_sign_out_id} onClick={() => void authguard_sign_out().then(authguard_after_sign_out)}><authguard_icons.LogOut size={16}/>{authguard_t('signOut')}</button>
    </div>}
  </div>
}
