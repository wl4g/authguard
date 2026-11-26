import * as authguard_react from 'react'
import { createRoot as authguard_create_root } from 'react-dom/client'
import * as authguard_access from './authguard-access'
import type { authguard_remote_props } from 'authguard/AccessManagement'
import { authguard_locale_options, type authguard_locale } from '../../../../../../web/src/shared/authguard_locales'
import { authguard_messages } from '../../../../../../web/src/shared/locales/authguard_messages'
import './authguard_host.css'

const authguard_icon_paths = {
  growth: 'M4 18V6m0 12h16M8 14l4-4 4 2 4-7',
  chevron: 'm6 9 6 6 6-6',
  access: 'M12 3 4 7v5c0 5 8 9 8 9s8-4 8-9V7l-8-4Zm-3 9 2 2 4-4',
  workspace: 'M3 4h18v16H3zM3 9h18M9 9v11',
}
function authguard_icon({ authguard_name }: { authguard_name: keyof typeof authguard_icon_paths }) {
  return <svg className="authguard-business-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={authguard_icon_paths[authguard_name]}/></svg>
}

const authguard_pages = {
  overview: authguard_react.lazy(() => import('authguard/Overview')),
  policy: authguard_react.lazy(() => import('authguard/Policy')),
  principals: authguard_react.lazy(() => import('authguard/Principals')),
  accountSecurity: authguard_react.lazy(() => import('authguard/AccountSecurity')),
}

function authguard_host() {
  const [authguard_path, authguard_set_path] = authguard_react.useState(location.pathname)
  const [authguard_locale, authguard_set_locale] = authguard_react.useState<authguard_locale>('en_US')
  const [authguard_theme, authguard_set_theme] = authguard_react.useState<'light' | 'dark' | 'system'>('light')
  const [authguard_draft, authguard_set_draft] = authguard_react.useState('Retained workspace')
  const [authguard_open, authguard_set_open] = authguard_react.useState(false)
  const authguard_dropdown = authguard_react.useRef<HTMLDivElement>(null)
  const [authguard_system_dark, authguard_set_system_dark] = authguard_react.useState(() => matchMedia('(prefers-color-scheme: dark)').matches)
  authguard_react.useEffect(() => {
    const authguard_media = matchMedia('(prefers-color-scheme: dark)')
    const authguard_apply = () => authguard_set_system_dark(authguard_media.matches)
    authguard_media.addEventListener('change', authguard_apply)
    return () => authguard_media.removeEventListener('change', authguard_apply)
  }, [])
  authguard_react.useEffect(() => {
    if (!authguard_open) return
    function authguard_dismiss(authguard_event: PointerEvent) {
      if (!authguard_dropdown.current?.contains(authguard_event.target as Node)) authguard_set_open(false)
    }
    document.addEventListener('pointerdown', authguard_dismiss)
    return () => document.removeEventListener('pointerdown', authguard_dismiss)
  }, [authguard_open])
  const authguard_previous = authguard_react.useRef('/jobs')
  const authguard_active = authguard_path.startsWith('/access-management')
  const authguard_t = (authguard_key: keyof typeof authguard_messages.en_US) => authguard_messages[authguard_locale][authguard_key]
  const authguard_functions = new URLSearchParams(location.search).get('settings') === 'functions'
  const authguard_settings = authguard_react.useRef<typeof import('authguard/settings') | null>(null)
  authguard_react.useEffect(() => {
    if (!authguard_functions || (!authguard_active && !authguard_settings.current)) return
    let authguard_cancelled = false
    function authguard_apply(authguard_api: typeof import('authguard/settings')) {
      if (authguard_cancelled) return
      authguard_settings.current = authguard_api
      authguard_api.authguard_set_locale(authguard_locale)
      authguard_api.authguard_set_theme(authguard_theme)
    }
    if (authguard_settings.current) authguard_apply(authguard_settings.current)
    else void import('authguard/settings').then(authguard_apply)
    return () => { authguard_cancelled = true }
  }, [authguard_active, authguard_functions, authguard_locale, authguard_theme])
  authguard_react.useEffect(() => {
    const authguard_pop = () => authguard_set_path(location.pathname)
    addEventListener('popstate', authguard_pop)
    return () => removeEventListener('popstate', authguard_pop)
  }, [])
  function authguard_navigate(authguard_next: string) {
    if (!authguard_active) authguard_previous.current = location.pathname
    history.pushState(null, '', authguard_next + (authguard_functions ? '?settings=functions' : ''))
    authguard_set_path(authguard_next); authguard_set_open(false)
  }
  const authguard_props: authguard_remote_props = {
    authguard_locale: authguard_functions ? undefined : authguard_locale,
    authguard_theme: authguard_functions ? undefined : authguard_theme,
    authguard_on_return: () => authguard_navigate(authguard_previous.current),
  }
  const authguard_selection = new URLSearchParams(location.search).get('modules')
  const authguard_only = new URLSearchParams(location.search).get('page') as keyof typeof authguard_pages | null
  const authguard_remote = { page: authguard_only ? authguard_pages[authguard_only] : null }
  return <div className="authguard-business-shell" data-authguard-host-theme={authguard_theme === 'system' ? (authguard_system_dark ? 'dark' : 'light') : authguard_theme}>
    <header className="authguard-business-header" data-testid="authguard-host-header">
      <div className="authguard-business-brand"><span className="authguard-business-mark"><authguard_components.icon authguard_name="growth"/></span><b>Customer Growth</b></div>
      <span className="authguard-business-breadcrumb">{authguard_active ? (authguard_t('authguard_access_management')) : (authguard_t('authguard_workspace'))}</span>
      <div className="authguard-business-dropdown" ref={authguard_dropdown} onKeyDown={authguard_event => {
        if (authguard_event.key === 'Escape') {
          authguard_set_open(false)
          authguard_dropdown.current?.querySelector<HTMLButtonElement>('button')?.focus()
        }
      }}>
        <button className="authguard-business-profile" data-testid="authguard-host-profile" aria-label={authguard_t('authguard_settings')} aria-expanded={authguard_open} aria-controls="authguard-business-menu" onClick={() => authguard_set_open(!authguard_open)}>
          <span className="authguard-business-avatar">AG</span><span className="authguard-business-user"><b>{authguard_t('authguard_admin')}</b><small>{authguard_t('authguard_workspace_settings')}</small></span><authguard_components.icon authguard_name="chevron"/>
        </button>
        {authguard_open && <div className="authguard-business-menu" id="authguard-business-menu" role="region" aria-label={authguard_t('authguard_workspace_settings')}>
          <div className="authguard-business-menu-heading"><b>{authguard_t('authguard_your_workspace')}</b><small>Customer Growth</small></div>
          <div className="authguard-business-menu-navigation">
            <button data-testid="authguard-host-access" onClick={() => authguard_navigate('/access-management')}><authguard_components.icon authguard_name="access"/>{authguard_t('authguard_access_management')}</button>
            <button data-testid="authguard-workspace" onClick={() => authguard_navigate(authguard_previous.current)}><authguard_components.icon authguard_name="workspace"/>{authguard_t('authguard_back')}</button>
          </div>
          <div className="authguard-business-preferences">
            <div className="authguard-business-preference-row authguard-business-language-row"><span>{authguard_t('language')}</span>
              <div className="authguard-business-segmented authguard-business-language-switch" role="group" aria-label={authguard_t('language')} data-testid="authguard-host-locale">
                {authguard_locale_options.map(authguard_option => <button type="button" key={authguard_option.value} data-testid={`authguard-host-locale-${authguard_option.value}`} title={authguard_option.name} aria-label={authguard_option.name} aria-pressed={authguard_locale === authguard_option.value} onClick={() => authguard_set_locale(authguard_option.value)}>{authguard_option.label}</button>)}
              </div>
            </div>
            <div className="authguard-business-preference-row"><span>{authguard_t('authguard_appearance')}</span>
              <div className="authguard-business-segmented" role="group" aria-label={authguard_t('authguard_appearance')} data-testid="authguard-host-theme">
                <button type="button" data-testid="authguard-host-theme-light" aria-pressed={authguard_theme === 'light' || (authguard_theme === 'system' && !authguard_system_dark)} onClick={() => authguard_set_theme('light')}>{authguard_t('light')}</button>
                <button type="button" data-testid="authguard-host-theme-dark" aria-pressed={authguard_theme === 'dark' || (authguard_theme === 'system' && authguard_system_dark)} onClick={() => authguard_set_theme('dark')}>{authguard_t('dark')}</button>
              </div>
            </div>
          </div>
        </div>}
      </div>
    </header>
    {authguard_active ? authguard_remote.page ? <authguard_react.Suspense fallback="Loading page…"><authguard_remote.page {...authguard_props}/></authguard_react.Suspense> : <authguard_access.authguard_access {...authguard_props} authguard_modules={authguard_selection ? authguard_selection.split(',') as authguard_remote_props['authguard_modules'] : undefined}/> :
      <div className="authguard-business-layout"><aside data-testid="authguard-business-sidebar"><button onClick={() => authguard_navigate('/jobs')}>{authguard_t('authguard_jobs')}</button><button data-testid="authguard-left-access" onClick={() => authguard_navigate('/access-management')}>{authguard_t('authguard_access_management')}</button></aside>
        <main><h1>{authguard_t('authguard_jobs')}</h1><label>{authguard_t('authguard_draft_job')}<input data-testid="authguard-business-draft" value={authguard_draft} onChange={authguard_event => authguard_set_draft(authguard_event.target.value)}/></label><button data-testid="authguard-host-sentinel" className="authguard-business-primary">{authguard_t('authguard_business_action')}</button></main>
      </div>}
  </div>
}
const authguard_components = { host: authguard_host, icon: authguard_icon }
authguard_create_root(document.getElementById('authguard-host-root')!).render(<authguard_react.StrictMode><authguard_components.host/></authguard_react.StrictMode>)
