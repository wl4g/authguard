import { Fingerprint, Github, KeyRound, MessageCircle, ScanFace, Shield, Sparkles } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../core/AuthContext'
import { authn, authnUrl, metadata as loadMetadata, type AuthMetadata, type LoginResponse } from '../core/api'
import { useI18n } from '../shared/i18n'
import { useApplicationTheme } from '../shared/ApplicationTheme'
import { Preferences } from '../shared/Preferences'
import { requestOptions, serializeAssertion } from './webauthn'
import { WalletLogin } from './WalletLogin'

const providerMark: Record<string, React.ReactNode> = {
  github: <Github/>, google: <span className="provider-letter">G</span>,
  wechat: <MessageCircle/>, qq: <span className="provider-letter">QQ</span>,
}

export function LoginPage() {
  const { t } = useI18n()
  const { accept } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const hosted = location.pathname === '/auth/login'
  const returnTo = new URLSearchParams(location.search).get('return_to') || (hosted ? '/' : '')
  const [meta, setMeta] = useState<AuthMetadata | null>(null)
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  useEffect(() => { loadMetadata().then(setMeta).catch(cause => setError(String(cause))) }, [])
  function authenticated(result: LoginResponse) {
    accept(result)
    if (hosted) {
      // AuthN has already normalized this to an allow-listed same-origin path.
      window.location.assign(result.returnUri || '/')
      return
    }
    navigate('/')
  }

  async function passwordLogin(event: FormEvent) {
    event.preventDefault(); if (!meta) return
    setBusy('password'); setError('')
    try {
      authenticated(await authn<LoginResponse>(meta.standalone.loginEndpoint, {
        method: 'POST', body: JSON.stringify({ login, password, totp: totp || null, returnTo }),
      }))
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy('') }
  }

  async function passkeyLogin() {
    if (!meta || !login) return
    setBusy('webauthn'); setError('')
    try {
      const challenge = await authn<{ challengeId: string; options: { publicKey: PublicKeyCredentialRequestOptionsJSON } }>(meta.standalone.webauthnAuthenticationChallengeEndpoint, {
        method: 'POST', body: JSON.stringify({ login }),
      })
      const credential = await navigator.credentials.get(requestOptions(challenge.options)) as PublicKeyCredential | null
      if (!credential) throw new Error('No WebAuthn assertion returned')
      authenticated(await authn<LoginResponse>(meta.standalone.webauthnAuthenticationVerifyEndpoint, {
        method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, credential: serializeAssertion(credential), returnTo }),
      }))
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy('') }
  }

  function oauthLogin(provider: AuthMetadata['oauth2']['providers'][number]) {
    setError('')
    setBusy(provider.id)
    // The full-page authorization-code redirect preserves the relying host;
    // callback sets the HttpOnly cookie then redirects to AuthN-approved return_to.
    window.location.assign(`${authnUrl(provider.authorizationEndpoint)}?return_to=${encodeURIComponent(returnTo || '/')}`)
  }

  // Application branding belongs only to the hosted relying-party surface.
  // The AuthGuard console keeps its own brand even if it shares a hostname in
  // a development topology.
  const brand = hosted ? meta?.application : null
  const brandName = brand?.displayName || t('product')
  useApplicationTheme(brand)

  return <div className="login-page">
    <div className="login-visual">
      <div className="visual-grid"/><div className="visual-glow"/>
      <div className="visual-brand">{brand?.logo ? <img src={brand.logo} alt=""/> : <Fingerprint/>}<b>{brandName}</b></div>
      <div className="trust-orbit"><span/><span/><span/><Shield/></div>
      <div className="visual-copy"><span className="eyebrow"><Sparkles size={14}/> AUTHN FABRIC / 01</span><h1>{t('loginTitle')}</h1><p>{t('loginHint')}</p></div>
      <div className="protocol-strip"><span>OIDC</span><span>RFC 6238</span><span>WebAuthn</span><span>CAIP-122</span></div>
    </div>
    <div className="login-panel">
      <div className="login-tools"><Preferences/></div>
      <div className="login-card">
        <div className="mobile-brand">{brand?.logo ? <img src={brand.logo} alt=""/> : <Fingerprint/>}<b>{brandName}</b></div>
        <h2>{hosted && brand ? `Sign in to ${brandName}` : t('login')}</h2><p>{t('authenticatedAs')} <code>canonical principal</code></p>
        <form onSubmit={passwordLogin}>
          <label>{t('loginId')}<input data-testid="login-id" autoComplete="username" value={login} onChange={event => setLogin(event.target.value)} required /></label>
          <label>{t('password')}<input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
          {meta?.standalone.totp && <label>{t('totp')}<input data-testid="login-totp" inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={event => setTotp(event.target.value)} /></label>}
          <button data-testid="login-password-submit" className="primary" disabled={busy !== '' || !meta?.standalone.password}><KeyRound size={18}/>{busy === 'password' ? t('connecting') : t('login')}</button>
        </form>
        {meta?.standalone.webauthn && <button data-testid="login-webauthn" className="auth-method" disabled={busy !== '' || !login} onClick={passkeyLogin}><ScanFace size={19}/><span>{t('passkey')}</span><i>FIDO2</i></button>}
        {meta && <WalletLogin metadata={meta} returnTo={returnTo} onAuthenticated={authenticated}/>}
        {!!meta?.oauth2.providers.length && <><div className="divider"><span>{t('orFederated')}</span></div><div className="provider-grid">{meta.oauth2.providers.map(provider => <button data-testid={`login-provider-${provider.id.toLowerCase()}`} key={provider.id} disabled={busy !== ''} onClick={() => oauthLogin(provider)}>{providerMark[provider.id.toLowerCase()] || <Shield/>}<span>{provider.id}</span></button>)}</div></>}
        {error && <div className="error-banner">{error}</div>}
        <div className="proof-line"><span/><small>{hosted ? 'Secured by AuthGuard' : 'Authentication ≠ Identity ≠ Principal ≠ Authorization'}</small></div>
      </div>
    </div>
  </div>
}

type PublicKeyCredentialRequestOptionsJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}
