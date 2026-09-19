import { Fingerprint, KeyRound, LogOut, ShieldCheck } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useAuth } from '../core/AuthContext'
import { authn, metadata as loadMetadata, type AuthMetadata, type LoginResponse } from '../core/api'
import { useApplicationTheme } from '../shared/ApplicationTheme'
import { useI18n } from '../shared/i18n'
import { Preferences } from '../shared/Preferences'
import { creationOptions, serializeRegistration } from '../login/webauthn'

type CreationOptionsJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string
  user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }
  excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}

export function SecurityPage() {
  const { authentication, accept, signOut } = useAuth()
  const { t } = useI18n()
  const [meta, setMeta] = useState<AuthMetadata | null>(null)
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [completed, setCompleted] = useState(false)

  useEffect(() => { loadMetadata().then(setMeta).catch(cause => setError(String(cause))) }, [])
  useApplicationTheme(meta?.application)

  async function registerPasskey(event: FormEvent) {
    event.preventDefault()
    if (!meta) return
    setBusy(true); setError(''); setCompleted(false)
    try {
      const challenge = await authn<{ challengeId: string; options: { publicKey: CreationOptionsJSON } }>(meta.standalone.webauthnRegistrationChallengeEndpoint, {
        method: 'POST', body: JSON.stringify({ login, password, totp: totp || null }),
      })
      const credential = await navigator.credentials.create(creationOptions(challenge.options)) as PublicKeyCredential | null
      if (!credential) throw new Error('No WebAuthn credential returned')
      const result = await authn<LoginResponse>(meta.standalone.webauthnRegistrationVerifyEndpoint, {
        method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, credential: serializeRegistration(credential) }),
      })
      accept(result)
      setCompleted(true)
      setPassword(''); setTotp('')
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy(false) }
  }

  const brand = meta?.application
  const principalId = authentication?.principal.principalId || ''
  const shortId = principalId.length > 18 ? `${principalId.slice(0, 10)}…${principalId.slice(-6)}` : principalId
  return <div className="account-security-page">
    <header className="account-security-header">
      <div className="visual-brand">{brand?.logo ? <img src={brand.logo} alt=""/> : <Fingerprint/>}<b>{brand?.displayName || t('product')}</b></div>
      <div className="account-security-tools"><Preferences/><button data-testid="account-sign-out" title={t('signOut')} onClick={() => void signOut().then(() => window.location.assign('/auth/login'))}><LogOut size={17}/></button></div>
    </header>
    <main className="security-card">
      <span className="eyebrow"><ShieldCheck size={14}/> {t('accountSecurity')}</span>
      <h1>{t('manageCredentials')}</h1>
      <p>{t('stepUpHint')}</p>
      <div className="principal-chip"><small>{t('principalId')}</small><code title={principalId}>{shortId}</code></div>
      <form onSubmit={registerPasskey}>
        <label>{t('loginId')}<input data-testid="security-login-id" autoComplete="username" value={login} onChange={event => setLogin(event.target.value)} required/></label>
        <label>{t('password')}<input data-testid="security-password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required/></label>
        {meta?.standalone.totp && <label>{t('totp')}<input data-testid="security-totp" inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={event => setTotp(event.target.value)}/></label>}
        <button data-testid="account-register-webauthn" className="primary" disabled={busy || !meta?.standalone.webauthn}><KeyRound size={18}/>{busy ? t('connecting') : t('registerPasskey')}</button>
      </form>
      {completed && <div data-testid="account-security-result" className="success-banner">{t('passkeyAdded')} · {authentication?.principal.amr.join(' + ')}</div>}
      {error && <div className="error-banner">{error}</div>}
      <button className="back-link" onClick={() => window.location.assign('/')}>{t('backToApplication')}</button>
    </main>
  </div>
}
