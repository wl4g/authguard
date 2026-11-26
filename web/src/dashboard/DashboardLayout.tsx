import { Fingerprint, Gauge, KeyRound, ShieldCheck, UsersRound } from 'lucide-react'
import { NavLink, Outlet } from 'react-router-dom'
import { useI18n } from '../shared/i18n'
import * as authguard_profile from '../shared/authguard_profile_menu'

export function DashboardLayout() {
  const { t } = useI18n()
  return <div className="authguard-app-shell">
    <aside className="authguard-sidebar">
      <div className="authguard-brand"><span><Fingerprint/></span><div><b>{t('product')}</b><small>{t('tagline')}</small></div></div>
      <nav>
        <NavLink to="/" end className={({ isActive: authguard_active }) => authguard_active ? 'authguard-active' : ''}><Gauge/>{t('overview')}</NavLink>
        <NavLink data-testid="nav-policy" to="/policy" className={({ isActive: authguard_active }) => authguard_active ? 'authguard-active' : ''}><ShieldCheck/>{t('policy')}</NavLink>
        <NavLink data-testid="nav-principals" to="/principals" className={({ isActive: authguard_active }) => authguard_active ? 'authguard-active' : ''}><UsersRound/>{t('principals')}</NavLink>
        <NavLink data-testid="nav-account-security" to="/auth/account/security" className={({ isActive: authguard_active }) => authguard_active ? 'authguard-active' : ''}><KeyRound/>{t('accountSecurity')}</NavLink>
      </nav>
      <div className="authguard-boundary-card"><KeyRound/><b>{t('secureBoundary')}</b><p>{t('securityCopy')}</p></div>
    </aside>
    <main>
      <header className="authguard-topbar"><authguard_profile.authguard_profile_menu/></header>
      <div className="authguard-page"><Outlet/></div>
    </main>
  </div>
}
