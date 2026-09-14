import { Fingerprint, Gauge, KeyRound, LogOut, ShieldCheck, UsersRound } from 'lucide-react'
import { NavLink, Outlet } from 'react-router-dom'
import { useState } from 'react'
import { useAuth } from '../features/auth/AuthContext'
import { useControl } from '../features/control/ControlContext'
import { useI18n } from '../lib/i18n'
import { Preferences } from './Preferences'

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
        <NavLink to="/policy"><ShieldCheck/>{t('policy')}</NavLink>
        <NavLink to="/principals"><UsersRound/>{t('principals')}</NavLink>
      </nav>
      <div className="boundary-card"><KeyRound/><b>{t('secureBoundary')}</b><p>{t('securityCopy')}</p></div>
    </aside>
    <main>
      <header className="topbar">
        <div className="control-token"><input type="password" value={draft} onChange={event => setDraft(event.target.value)} placeholder={t('controlToken')}/><button onClick={() => setToken(draft)}>{t('saveToken')}</button></div>
        <Preferences/>
        <div className="profile"><span>{authentication?.principal.principalId}</span><button title={t('signOut')} onClick={signOut}><LogOut size={17}/></button></div>
      </header>
      <div className="page"><Outlet/></div>
    </main>
  </div>
}
