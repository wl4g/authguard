import { Binary, Braces, Network, Orbit } from 'lucide-react'
import { useAuth } from '../core/AuthContext'
import { useI18n } from '../shared/i18n'

export function OverviewPage() {
  const { authentication } = useAuth()
  const { t } = useI18n()
  const principalId = authentication?.principal.principalId || ''
  const shortId = principalId.length > 18 ? `${principalId.slice(0, 10)}…${principalId.slice(-6)}` : principalId
  return <section>
    <div className="page-heading"><div><span className="eyebrow">AUTHENTICATION → PRINCIPAL → TOKEN</span><h1>{t('welcome')}</h1><p>{t('welcomeCopy')}</p></div><Orbit className="hero-orbit"/></div>
    <div className="metric-grid">
      <article><Network/><small>PRINCIPAL</small><strong className="principal-id-display" title={principalId}>{shortId}</strong><p>{authentication?.principal.kind} · <button data-testid="copy-principal-id" className="inline-copy" onClick={() => void navigator.clipboard.writeText(principalId)}>{t('copyId')}</button></p></article>
      <article><Binary/><small>AMR</small><strong data-testid="authentication-amr">{authentication?.principal.amr.join(' + ') || '—'}</strong><p>{authentication?.principal.acr || 'baseline assurance'}</p></article>
      <article><Braces/><small>BOUNDARY</small><strong>Protocol neutral</strong><p>AuthZ input: principal_id · resource · action · context</p></article>
    </div>
  </section>
}
