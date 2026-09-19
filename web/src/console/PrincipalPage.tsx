import { CloudDownload, Plus, RefreshCw, Search, ToggleLeft, ToggleRight, Trash2, UserRound, X } from 'lucide-react'
import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useControl } from '../core/ControlContext'
import { authn, control, metadata, type LoginResponse, type Principal } from '../core/api'
import { useI18n } from '../shared/i18n'

type PrincipalPageData = { total: number; items: Principal[]; next_cursor?: string }
type Projection = { reference: { provider_id: string; issuer: string; external_id: string }; kind: Principal['kind']; display_name: string; username?: string; email?: string; enabled: boolean }

export function PrincipalPage() {
  const { t } = useI18n(); const { token } = useControl()
  const [page, setPage] = useState<PrincipalPageData>({ total: 0, items: [] }); const [query, setQuery] = useState('')
  const [mode, setMode] = useState<'local' | 'federated' | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const load = useCallback(async () => {
    if (!token) return
    setBusy(true); setError('')
    try { setPage(await control<PrincipalPageData>(`/api/v1/principals?query=${encodeURIComponent(query)}&limit=50`, token)) }
    catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy(false) }
  }, [query, t, token])
  useEffect(() => { void load() }, [load])
  async function status(principal: Principal) {
    try { await control(`/api/v1/principals/${encodeURIComponent(principal.id)}`, token, { method: 'PATCH', body: JSON.stringify({ status: principal.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE' }) }); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
  }
  async function remove(principal: Principal) {
    if (!confirm(`${t('remove')} ${principal.id}?`)) return
    try { await control(`/api/v1/principals/${encodeURIComponent(principal.id)}`, token, { method: 'DELETE' }); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
  }
  return <section>
    <div className="page-heading compact"><div><span className="eyebrow">CANONICAL IDENTITY</span><h1>{t('principals')}</h1><p>{page.total} canonical principals</p></div><button className="icon-button" onClick={load}><RefreshCw className={busy ? 'spin' : ''}/></button></div>
    <div className="data-card"><div className="data-toolbar"><div className="search-box"><Search/><input value={query} onChange={event => setQuery(event.target.value)} onKeyDown={event => event.key === 'Enter' && load()} placeholder={t('search')}/></div><div><button data-testid="principal-federated-open" onClick={() => setMode('federated')}><CloudDownload/>{t('federatedSearch')}</button><button data-testid="principal-local-open" className="primary small" onClick={() => setMode('local')}><Plus/>{t('localCreate')}</button></div></div>
      {error && <div className="error-banner">{error}</div>}
      {!page.items.length ? <div className="empty"><UserRound/><p>{token ? t('empty') : t('controlToken')}</p></div> : <div className="principal-table" data-testid="principal-list"><div className="table-head"><span>{t('principalId')}</span><span>{t('displayName')}</span><span>{t('kind')}</span><span>{t('status')}</span><span/></div>{page.items.map(principal => <div className="table-row" key={principal.id}><code>{principal.id}</code><strong>{principal.display_name}</strong><span>{principal.kind}</span><span className={`status ${principal.status.toLowerCase()}`}>{principal.status}</span><div className="row-actions"><button title={principal.status === 'ACTIVE' ? t('disabled') : t('active')} onClick={() => status(principal)}>{principal.status === 'ACTIVE' ? <ToggleRight/> : <ToggleLeft/>}</button><button className="danger" onClick={() => remove(principal)}><Trash2/></button></div></div>)}</div>}
    </div>
    {mode === 'local' && (
      <LocalAccountDialog onClose={() => setMode(null)} onCreated={async () => { setMode(null); await load() }}/>
    )}
    {mode === 'federated' && (
      <FederatedDialog token={token} onClose={() => setMode(null)} onCreated={async () => { setMode(null); await load() }}/>
    )}
  </section>
}

function LocalAccountDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => Promise<void> }) {
  const { t } = useI18n(); const [login, setLogin] = useState(''); const [displayName, setDisplayName] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(''); try { const meta = await metadata(); await authn<LoginResponse>(meta.standalone.registrationEndpoint, { method: 'POST', body: JSON.stringify({ login, displayName, password }) }); await onCreated() } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')); setBusy(false) } }
  return <div className="modal-backdrop"><form className="modal narrow" onSubmit={submit}><header><div><span className="eyebrow">STANDALONE</span><h3>{t('localCreate')}</h3></div><button type="button" onClick={onClose}><X/></button></header><label>{t('username')}<input data-testid="principal-local-login" value={login} onChange={event => setLogin(event.target.value)} required/></label><label>{t('displayName')}<input data-testid="principal-local-display-name" value={displayName} onChange={event => setDisplayName(event.target.value)} required/></label><label>{t('password')}<input data-testid="principal-local-password" type="password" value={password} onChange={event => setPassword(event.target.value)} required/></label>{error && <div className="error-banner">{error}</div>}<footer><button type="button" onClick={onClose}>{t('cancel')}</button><button data-testid="principal-local-submit" className="primary" disabled={busy}>{t('createAccount')}</button></footer></form></div>
}

function FederatedDialog({ token, onClose, onCreated }: { token: string; onClose: () => void; onCreated: () => Promise<void> }) {
  const { t } = useI18n(); const [text, setText] = useState(''); const [results, setResults] = useState<Projection[]>([]); const [principalId, setPrincipalId] = useState(''); const [selected, setSelected] = useState<Projection | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function search(event: FormEvent) { event.preventDefault(); setBusy(true); setError(''); try { const page = await control<{ principals: Projection[] }>('/api/v1/principal-discovery/search', token, { method: 'POST', body: JSON.stringify({ text, kinds: ['USER'], provider_ids: [], per_provider_limit: 20, cursors: {} }) }); setResults(page.principals) } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) } finally { setBusy(false) } }
  async function materialize() { if (!selected || !principalId) return; setBusy(true); setError(''); try { await control('/api/v1/principal-discovery/materialize', token, { method: 'POST', body: JSON.stringify({ principal_id: principalId, reference: selected.reference }) }); await onCreated() } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')); setBusy(false) } }
  return <div className="modal-backdrop"><div className="modal"><header><div><span className="eyebrow">FEDERATED DISCOVERY</span><h3>{t('federatedSearch')}</h3></div><button onClick={onClose}><X/></button></header><form className="inline-search" onSubmit={search}><input data-testid="principal-federated-query" value={text} onChange={event => setText(event.target.value)} required placeholder={t('search')}/><button data-testid="principal-federated-search" className="primary" disabled={busy}><Search/></button></form><div className="discovery-list" data-testid="principal-federated-results">{results.map(result => <button className={selected === result ? 'selected' : ''} onClick={() => { setSelected(result); setPrincipalId(`P_${result.reference.external_id}`) }} key={`${result.reference.issuer}:${result.reference.external_id}`}><strong>{result.display_name}</strong><span>{result.email || result.username || result.reference.external_id}</span><small>{result.reference.provider_id}</small></button>)}</div>{selected && <label>{t('principalId')}<input data-testid="principal-federated-id" value={principalId} onChange={event => setPrincipalId(event.target.value)}/></label>}{error && <div className="error-banner">{error}</div>}<footer><button onClick={onClose}>{t('cancel')}</button><button data-testid="principal-federated-materialize" className="primary" disabled={!selected || !principalId || busy} onClick={materialize}>{t('materialize')}</button></footer></div></div>
}
