import { Binary, Braces, Network, Orbit } from 'lucide-react'
import { useAuth } from '../features/auth/AuthContext'
import { useI18n } from '../lib/i18n'

export function OverviewPage() {
  const { authentication } = useAuth()
  const { t } = useI18n()
  return <section>
    <div className="page-heading"><div><span className="eyebrow">AUTHENTICATION → PRINCIPAL → TOKEN</span><h1>{t('welcome')}</h1><p>{t('welcomeCopy')}</p></div><Orbit className="hero-orbit"/></div>
    <div className="metric-grid">
      <article><Network/><small>PRINCIPAL</small><strong>{authentication?.principal.principalId}</strong><p>{authentication?.principal.kind}</p></article>
      <article><Binary/><small>AMR</small><strong>{authentication?.principal.amr.join(' + ') || '—'}</strong><p>{authentication?.principal.acr || 'baseline assurance'}</p></article>
      <article><Braces/><small>BOUNDARY</small><strong>Protocol neutral</strong><p>AuthZ input: principal_id · resource · action · context</p></article>
    </div>
  </section>
}
