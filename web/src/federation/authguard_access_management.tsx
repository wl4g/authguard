import * as authguard_react from 'react'
import * as authguard_boundary from './authguard_boundary'
import * as authguard_i18n from '../shared/i18n'
import * as authguard_overview from '../dashboard/OverviewPage'

const authguard_pages = {
  overview: authguard_overview.OverviewPage,
  policy: authguard_react.lazy(() => import('../dashboard/PolicyPage').then(authguard_module => ({ default: authguard_module.PolicyPage }))),
  principals: authguard_react.lazy(() => import('../dashboard/PrincipalPage').then(authguard_module => ({ default: authguard_module.PrincipalPage }))),
  accountSecurity: authguard_react.lazy(() => import('../account/SecurityPage').then(authguard_module => ({ default: () => <authguard_module.SecurityPage authguard_embedded/> }))),
}
export type authguard_module_id = keyof typeof authguard_pages
export type authguard_access_props = authguard_boundary.authguard_remote_props & { authguard_modules?: readonly authguard_module_id[] }
const authguard_all_modules = Object.keys(authguard_pages) as authguard_module_id[]

function authguard_content(authguard_props: authguard_access_props) {
  const { t: authguard_t } = authguard_i18n.useI18n()
  const authguard_modules = authguard_props.authguard_modules ?? authguard_all_modules
  const [authguard_selected, authguard_select] = authguard_react.useState<authguard_module_id>(authguard_modules[0] ?? 'overview')
  const authguard_current = authguard_modules.includes(authguard_selected) ? authguard_selected : authguard_modules[0]
  const authguard_components = { page: authguard_current ? authguard_pages[authguard_current] : null }
  return <div className="authguard-management" data-testid="authguard-management">
    <aside className="authguard-management-sidebar">
      <b>{authguard_t('authguard_access_management')}</b>
      <nav aria-label={authguard_t('authguard_access_management')}>{authguard_modules.map(authguard_module => <button type="button" key={authguard_module} data-testid={`authguard-nav-${authguard_module}`} className={authguard_current === authguard_module ? 'authguard-active' : ''} aria-current={authguard_current === authguard_module ? 'page' : undefined} onClick={() => authguard_select(authguard_module)}>{authguard_t(authguard_module)}</button>)}</nav>
      <button className="authguard-return" data-testid="authguard-return" onClick={authguard_props.authguard_on_return}>{authguard_t('authguard_back')}</button>
    </aside>
    <main className="authguard-management-page"><authguard_react.Suspense fallback={<div role="status">{authguard_t('connecting')}</div>}>{authguard_components.page && <authguard_components.page/>}</authguard_react.Suspense></main>
  </div>
}
const authguard_components = { content: authguard_content }
export default function authguard_access_management(authguard_props: authguard_access_props) {
  return <authguard_boundary.authguard_boundary {...authguard_props}><authguard_components.content {...authguard_props}/></authguard_boundary.authguard_boundary>
}
