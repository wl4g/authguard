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
  github: <Github/>, google: <span className="authguard-provider-letter">G</span>,
  wechat: <MessageCircle/>, qq: <span className="authguard-provider-letter">QQ</span>,
}

export function LoginPage() {
  const { t } = useI18n()
  const { accept } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const hosted = location.pathname === '/auth/login'
  const returnTo = new URLSearchParams(location.search).get('return_to') || (hosted ? '/' : '')
  const [meta, setMeta] = useState<AuthMetadata | null>(null)
  const [passwordSource, setPasswordSource] = useState<'standalone' | 'ldap'>('standalone')
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  useEffect(() => { loadMetadata().then(value => { setMeta(value); if (value.ldap?.enabled) setPasswordSource('ldap') }).catch(cause => setError(String(cause))) }, [])
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
      const endpoint = passwordSource === 'ldap' ? meta.ldap.loginEndpoint : meta.standalone.loginEndpoint
      authenticated(await authn<LoginResponse>(endpoint, {
        method: 'POST', body: JSON.stringify(passwordSource === 'ldap' ? { login, password, returnTo } : { login, password, totp: totp || null, returnTo }),
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
      if (!credential) throw new Error(t('authguard_no_passkey'))
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
  // The AuthGuard Dashboard keeps its own brand even if it shares a hostname in
  // a development topology.
  const brand = hosted ? meta?.application : null
  const brandName = brand?.displayName || t('product')
  useApplicationTheme(brand)

  return <div className="authguard-login-page">
    <div className="authguard-login-visual">
      <div className="authguard-visual-grid"/><div className="authguard-visual-glow"/>
      <div className="authguard-visual-brand">{brand?.logo ? <img src={brand.logo} alt=""/> : <Fingerprint/>}<b>{brandName}</b></div>
      <div className="authguard-trust-orbit"><span/><span/><span/><Shield/></div>
      <div className="authguard-visual-copy"><span className="authguard-eyebrow"><Sparkles size={14}/> AUTHN FABRIC / 01</span><h1>{t('loginTitle')}</h1><p>{t('loginHint')}</p></div>
      <div className="authguard-protocol-strip"><span>OIDC</span><span>RFC 6238</span><span>WebAuthn</span><span>CAIP-122</span></div>
    </div>
    <div className="authguard-login-panel">
      <div className="authguard-login-tools"><Preferences/></div>
      <div className="authguard-login-card">
        <div className="authguard-mobile-brand">{brand?.logo ? <img src={brand.logo} alt=""/> : <Fingerprint/>}<b>{brandName}</b></div>
        <h2>{hosted && brand ? `${t('signInTo')} ${brandName}` : t('login')}</h2><p>{t('authenticatedAs')} <code>canonical principal</code></p>
        <form onSubmit={passwordLogin}>
          {meta?.ldap?.enabled && meta.standalone.enabled && <label>{t('provider')}<select data-testid="login-password-source" value={passwordSource} disabled={busy !== ''} onChange={event => { setPasswordSource(event.target.value as 'standalone' | 'ldap'); setPassword(''); setTotp('') }}><option value="ldap">{t('directoryAccount')}</option><option value="standalone">{t('localAccount')}</option></select></label>}
          <label>{t('loginId')}<input data-testid="login-id" autoComplete="username" value={login} onChange={event => setLogin(event.target.value)} required /></label>
          <label>{t('password')}<input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
          {passwordSource === 'standalone' && meta?.standalone.totp && <label>{t('totp')}<input data-testid="login-totp" inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={event => setTotp(event.target.value)} /></label>}
          <button data-testid="login-password-submit" className="authguard-primary" disabled={busy !== '' || !(passwordSource === 'ldap' ? meta?.ldap?.enabled : meta?.standalone.password)}><KeyRound size={18}/>{busy === 'password' ? t('connecting') : t('login')}</button>
        </form>
        {meta?.standalone.webauthn && <button data-testid="login-webauthn" className="authguard-auth-method" disabled={busy !== '' || !login} onClick={passkeyLogin}><ScanFace size={19}/><span>{t('passkey')}</span><i>FIDO2</i></button>}
        {meta && <WalletLogin metadata={meta} returnTo={returnTo} onAuthenticated={authenticated}/>}
        {!!meta?.oauth2.providers.length && <><div className="authguard-divider"><span>{t('orFederated')}</span></div><div className="authguard-provider-grid">{meta.oauth2.providers.map(provider => <button data-testid={`login-provider-${provider.id.toLowerCase()}`} key={provider.id} disabled={busy !== ''} onClick={() => oauthLogin(provider)}>{providerMark[provider.id.toLowerCase()] || <Shield/>}<span>{provider.id}</span></button>)}</div></>}
        {error && <div className="authguard-error-banner">{error}</div>}
        <div className="authguard-proof-line"><span/><small>{hosted ? t('authguard_secured_by') : t('authguard_auth_boundary')}</small></div>
      </div>
    </div>
  </div>
}

type PublicKeyCredentialRequestOptionsJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}
