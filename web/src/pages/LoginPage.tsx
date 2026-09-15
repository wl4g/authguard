import { Fingerprint, Github, KeyRound, MessageCircle, ScanFace, Shield, Sparkles, UserPlus } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../features/auth/AuthContext'
import { WalletLogin } from '../features/auth/WalletLogin'
import { authn, authnUrl, metadata as loadMetadata, type AuthMetadata, type LoginResponse } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { creationOptions, requestOptions, serializeAssertion, serializeRegistration } from '../lib/webauthn'
import { Preferences } from '../components/Preferences'

const providerMark: Record<string, React.ReactNode> = {
  github: <Github/>, google: <span className="provider-letter">G</span>,
  wechat: <MessageCircle/>, qq: <span className="provider-letter">QQ</span>,
}

export function LoginPage() {
  const { t } = useI18n()
  const { accept } = useAuth()
  const navigate = useNavigate()
  const [meta, setMeta] = useState<AuthMetadata | null>(null)
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  useEffect(() => { loadMetadata().then(setMeta).catch(cause => setError(String(cause))) }, [])
  function authenticated(result: LoginResponse) { accept(result); navigate('/') }

  async function passwordLogin(event: FormEvent) {
    event.preventDefault(); if (!meta) return
    setBusy('password'); setError('')
    try {
      authenticated(await authn<LoginResponse>(meta.standalone.loginEndpoint, {
        method: 'POST', body: JSON.stringify({ login, password, totp: totp || null }),
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
        method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, credential: serializeAssertion(credential) }),
      }))
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy('') }
  }

  async function registerPasskey() {
    if (!meta || !login || !password) return
    setBusy('webauthn-registration'); setError('')
    try {
      const challenge = await authn<{ challengeId: string; options: { publicKey: PublicKeyCredentialCreationOptionsJSON } }>(meta.standalone.webauthnRegistrationChallengeEndpoint, {
        method: 'POST', body: JSON.stringify({ login, password, totp: totp || null, displayName: login }),
      })
      const credential = await navigator.credentials.create(creationOptions(challenge.options)) as PublicKeyCredential | null
      if (!credential) throw new Error('No WebAuthn credential returned')
      authenticated(await authn<LoginResponse>(meta.standalone.webauthnRegistrationVerifyEndpoint, {
        method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, credential: serializeRegistration(credential) }),
      }))
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy('') }
  }

  function oauthLogin(provider: AuthMetadata['oauth2']['providers'][number]) {
    setError('')
    const returnUri = `${window.location.origin}/login`
    const popup = window.open(`${authnUrl(provider.authorizationEndpoint)}?return_uri=${encodeURIComponent(returnUri)}`, `authguard-${provider.id}`, 'popup,width=520,height=720')
    if (!popup) { setError('Popup was blocked'); return }
    setBusy(provider.id)
    const timer = window.setInterval(() => {
      if (popup.closed) { clearInterval(timer); setBusy(''); return }
      try {
        const text = popup.document.body?.innerText?.trim()
        if (!text?.startsWith('{')) return
        const result = JSON.parse(text) as LoginResponse & { code?: string; message?: string }
        if (!result.accessToken) throw new Error(result.message || result.code || 'OAuth callback failed')
        clearInterval(timer); popup.close(); setBusy(''); authenticated(result)
      } catch (cause) {
        if (cause instanceof DOMException) return
        clearInterval(timer); popup.close(); setBusy('')
        setError(cause instanceof Error ? cause.message : t('apiError'))
      }
    }, 350)
  }

  return <div className="login-page">
    <div className="login-visual">
      <div className="visual-grid"/><div className="visual-glow"/>
      <div className="visual-brand"><Fingerprint/><b>{t('product')}</b></div>
      <div className="trust-orbit"><span/><span/><span/><Shield/></div>
      <div className="visual-copy"><span className="eyebrow"><Sparkles size={14}/> AUTHN FABRIC / 01</span><h1>{t('loginTitle')}</h1><p>{t('loginHint')}</p></div>
      <div className="protocol-strip"><span>OIDC</span><span>RFC 6238</span><span>WebAuthn</span><span>CAIP-122</span></div>
    </div>
    <div className="login-panel">
      <div className="login-tools"><Preferences/></div>
      <div className="login-card">
        <div className="mobile-brand"><Fingerprint/><b>{t('product')}</b></div>
        <h2>{t('login')}</h2><p>{t('authenticatedAs')} <code>canonical principal</code></p>
        <form onSubmit={passwordLogin}>
          <label>{t('loginId')}<input data-testid="login-id" autoComplete="username" value={login} onChange={event => setLogin(event.target.value)} required /></label>
          <label>{t('password')}<input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
          {meta?.standalone.totp && <label>{t('totp')}<input data-testid="login-totp" inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={event => setTotp(event.target.value)} /></label>}
          <button data-testid="login-password-submit" className="primary" disabled={busy !== '' || !meta?.standalone.password}><KeyRound size={18}/>{busy === 'password' ? t('connecting') : t('login')}</button>
        </form>
        {meta?.standalone.webauthn && <><button data-testid="login-webauthn" className="auth-method" disabled={busy !== '' || !login} onClick={passkeyLogin}><ScanFace size={19}/><span>{t('passkey')}</span><i>FIDO2</i></button><button data-testid="register-webauthn" className="auth-method" disabled={busy !== '' || !login || !password} onClick={registerPasskey}><UserPlus size={19}/><span>{t('registerPasskey')}</span><i>FIDO2</i></button></>}
        {meta && <WalletLogin metadata={meta} onAuthenticated={authenticated}/>}
        {!!meta?.oauth2.providers.length && <><div className="divider"><span>{t('orFederated')}</span></div><div className="provider-grid">{meta.oauth2.providers.map(provider => <button data-testid={`login-provider-${provider.id.toLowerCase()}`} key={provider.id} disabled={busy !== ''} onClick={() => oauthLogin(provider)}>{providerMark[provider.id.toLowerCase()] || <Shield/>}<span>{provider.id}</span></button>)}</div></>}
        {error && <div className="error-banner">{error}</div>}
        <div className="proof-line"><span/><small>Authentication ≠ Identity ≠ Principal ≠ Authorization</small></div>
      </div>
    </div>
  </div>
}

type PublicKeyCredentialRequestOptionsJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}

type PublicKeyCredentialCreationOptionsJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string
  user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }
  excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}
