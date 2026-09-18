import { Braces, Pencil, Plus, RefreshCw, Trash2, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useControl } from '../core/ControlContext'
import { control } from '../core/api'
import { useI18n } from '../shared/i18n'

type Resource = Record<string, unknown>
type Collection = { policy_revision: number; total: number; items: Resource[] }
type ResourceType = 'actions' | 'roles' | 'role-bindings'

const definitions: Record<ResourceType, { id: string; initial: Resource }> = {
  actions: { id: 'identifier', initial: { identifier: 'resource.read', description: '', route_matchers: [] } },
  roles: { id: 'id', initial: { id: 'role-reader', name: 'Reader', description: '', action_ids: [] } },
  'role-bindings': { id: 'id', initial: { id: 'binding-reader', principal_id: '', role_id: '', effect: 'ALLOW', resource_urn: 'urn:authguard:*', conditions: {} } },
}

export function PolicyPage() {
  const { t } = useI18n(); const { token } = useControl()
  const [type, setType] = useState<ResourceType>('actions')
  const [collection, setCollection] = useState<Collection>({ policy_revision: 0, total: 0, items: [] })
  const [editing, setEditing] = useState<Resource | null>(null)
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const definition = definitions[type]
  const load = useCallback(async () => {
    if (!token) return
    setBusy(true); setError('')
    try { setCollection(await control<Collection>(`/api/v1/${type}`, token)) }
    catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy(false) }
  }, [token, type, t])
  useEffect(() => { void load() }, [load])
  const labels = useMemo<Record<ResourceType, string>>(() => ({ actions: t('actions'), roles: t('roles'), 'role-bindings': t('bindings') }), [t])

  async function save(resource: Resource, original: Resource | null) {
    const id = String(resource[definition.id] || '')
    if (!id) throw new Error(`${definition.id} is required`)
    await control(`/api/v1/${type}${original ? `/${encodeURIComponent(String(original[definition.id]))}` : ''}`, token, {
      method: original ? 'PUT' : 'POST', headers: { 'if-match': String(collection.policy_revision) }, body: JSON.stringify(resource),
    })
    setEditing(null); await load()
  }
  async function remove(resource: Resource) {
    if (!confirm(`${t('remove')} ${String(resource[definition.id])}?`)) return
    try {
      await control(`/api/v1/${type}/${encodeURIComponent(String(resource[definition.id]))}`, token, { method: 'DELETE', headers: { 'if-match': String(collection.policy_revision) } })
      await load()
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
  }

  return <section>
    <div className="page-heading compact"><div><span className="eyebrow">PAP / CAS</span><h1>{t('policy')}</h1><p>{t('revision')} {collection.policy_revision}</p></div><button className="icon-button" onClick={load}><RefreshCw className={busy ? 'spin' : ''}/></button></div>
    <div className="tabbar">{(Object.keys(definitions) as ResourceType[]).map(item => <button data-testid={`policy-tab-${item}`} className={type === item ? 'active' : ''} onClick={() => setType(item)} key={item}>{labels[item]}</button>)}</div>
    <div className="data-card">
      <div className="data-toolbar"><span>{collection.total} {labels[type].toLowerCase()}</span><button data-testid="policy-create" className="primary small" disabled={!token} onClick={() => setEditing({ ...definition.initial })}><Plus/>{t('add')}</button></div>
      {error && <div className="error-banner">{error}</div>}
      {!collection.items.length ? <div className="empty"><Braces/><p>{token ? t('empty') : t('controlToken')}</p></div> : <div className="resource-list">{collection.items.map(resource => {
        const id = String(resource[definition.id]); return <article key={id}><div><strong>{id}</strong><p>{resource.description as string || resource.name as string || resource.role_id as string || '—'}</p></div><code>{JSON.stringify(resource)}</code><div className="row-actions"><button onClick={() => setEditing(resource)}><Pencil/></button><button className="danger" onClick={() => remove(resource)}><Trash2/></button></div></article>
      })}</div>}
    </div>
    {editing && <JsonDialog title={`${editing[definition.id] ? t('edit') : t('add')} ${labels[type]}`} value={editing} isNew={!collection.items.includes(editing)} onClose={() => setEditing(null)} onSave={save}/>}
  </section>
}

function JsonDialog({ title, value, isNew, onClose, onSave }: { title: string; value: Resource; isNew: boolean; onClose: () => void; onSave: (value: Resource, original: Resource | null) => Promise<void> }) {
  const { t } = useI18n(); const [text, setText] = useState(() => JSON.stringify(value, null, 2)); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit() { setBusy(true); setError(''); try { await onSave(JSON.parse(text) as Resource, isNew ? null : value) } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')); setBusy(false) } }
  return <div className="modal-backdrop"><div className="modal"><header><div><span className="eyebrow">JSON RESOURCE</span><h3>{title}</h3></div><button onClick={onClose}><X/></button></header><label>{t('json')}<textarea data-testid="policy-json" rows={17} spellCheck={false} value={text} onChange={event => setText(event.target.value)}/></label>{error && <div className="error-banner">{error}</div>}<footer><button onClick={onClose}>{t('cancel')}</button><button data-testid="policy-save" className="primary" disabled={busy} onClick={submit}>{t('save')}</button></footer></div></div>
}
