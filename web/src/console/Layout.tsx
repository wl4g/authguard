import { Fingerprint, Gauge, KeyRound, LogOut, ShieldCheck, UsersRound } from 'lucide-react'
import { NavLink, Outlet } from 'react-router-dom'
import { useState } from 'react'
import { useAuth } from '../core/AuthContext'
import { useControl } from '../core/ControlContext'
import { useI18n } from '../shared/i18n'
import { Preferences } from '../shared/Preferences'

export function Layout() {
  const { authentication, signOut } = useAuth()
  const { token, setToken } = useControl()
  const { t } = useI18n()
  const [draft, setDraft] = useState(token)
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span><Fingerprint/></span><div><b>{t('product')}</b><small>{t('tagline')}</small></div></div>
      <nav>
        <NavLink to="/" end><Gauge/>{t('overview')}</NavLink>
        <NavLink data-testid="nav-policy" to="/policy"><ShieldCheck/>{t('policy')}</NavLink>
        <NavLink data-testid="nav-principals" to="/principals"><UsersRound/>{t('principals')}</NavLink>
        <NavLink data-testid="nav-account-security" to="/auth/account/security"><KeyRound/>{t('accountSecurity')}</NavLink>
      </nav>
      <div className="boundary-card"><KeyRound/><b>{t('secureBoundary')}</b><p>{t('securityCopy')}</p></div>
    </aside>
    <main>
      <header className="topbar">
        <div className="control-token"><input data-testid="control-token" type="password" value={draft} onChange={event => setDraft(event.target.value)} placeholder={t('controlToken')}/><button data-testid="control-token-submit" onClick={() => setToken(draft)}>{t('saveToken')}</button></div>
        <Preferences/>
        <div className="profile"><span data-testid="authenticated-principal" title={authentication?.principal.principalId}>{authentication?.principal.principalId}</span><button data-testid="sign-out" title={t('signOut')} onClick={() => void signOut()}><LogOut size={17}/></button></div>
      </header>
      <div className="page"><Outlet/></div>
    </main>
  </div>
}
