import { Binary, Braces, Network, Orbit } from 'lucide-react'
import { useAuth } from '../core/AuthContext'
import { useI18n } from '../shared/i18n'

export function OverviewPage() {
  const { authentication } = useAuth()
  const { t } = useI18n()
  const principalId = authentication?.principal.principalId || ''
  const shortId = principalId.length > 18 ? `${principalId.slice(0, 10)}…${principalId.slice(-6)}` : principalId
  return <section>
    <div className="authguard-page-heading"><div><span className="authguard-eyebrow">AUTHENTICATION → PRINCIPAL → TOKEN</span><h1>{t('welcome')}</h1><p>{t('welcomeCopy')}</p></div><Orbit className="authguard-hero-orbit"/></div>
    <div className="authguard-metric-grid">
      <article><Network/><small>PRINCIPAL</small><strong className="authguard-principal-id-display" title={principalId}>{shortId}</strong><p>{authentication?.principal.kind} · <button data-testid="copy-principal-id" className="authguard-inline-copy" onClick={() => void navigator.clipboard.writeText(principalId)}>{t('copyId')}</button></p></article>
      <article><Binary/><small>AMR</small><strong data-testid="authentication-amr">{authentication?.principal.amr.join(' + ') || '—'}</strong><p>{authentication?.principal.acr || t('authguard_baseline_assurance')}</p></article>
      <article><Braces/><small>{t('authguard_boundary')}</small><strong>{t('authguard_protocol_neutral')}</strong><p>{t('authguard_authorization_input')}</p></article>
    </div>
  </section>
}
