import { Fragment, useEffect, useState } from 'react'
import { api } from '../api.js'

const TEXT = [
  ['services', 'Services they provide', 'For example: payroll processing'],
  ['business_owner', 'Business owner (our side)', 'Who in your company owns this vendor'],
  ['contact_name', 'Vendor contact name', ''],
  ['contact_email', 'Vendor contact email', ''],
  ['country', 'Country', 'Where the vendor processes your data'],
  ['spend', 'Annual spend', 'Optional'],
]
const DATA = ['Customer personal data', 'Employee data', 'Payment card data', 'Financial records', 'Health data', 'Source code', 'Credentials or keys', 'Internal documents']

export default function VendorProfile({ entityId, user }) {
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const [p, setP] = useState(null)
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { api.getProfile(entityId).then(setP).catch(() => {}) }, [entityId])
  if (!p) return null
  const d = p.details
  const ob = p.offboarding
  const has = Object.values(d).some((v) => v && (!Array.isArray(v) || v.length))

  async function save(e) {
    e.preventDefault(); setError(null)
    try { setP(await api.setProfile(entityId, form)); setForm(null) } catch (err) { setError(err.message) }
  }
  async function start() { try { setP(await api.startOffboarding(entityId)) } catch (err) { setError(err.message) } }
  async function tick(key, done) { try { setP(await api.tickOffboarding(entityId, key, done)) } catch (err) { setError(err.message) } }
  const toggle = (t) => { const cur = form.data_types || []; setForm({ ...form, data_types: cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t] }) }

  return (
    <section className="card">
      <div className="section-head">
        <div>
          <h2>Vendor details</h2>
          <p className="muted small">What this vendor does for you, who owns the relationship and when the contract ends. You get an alert 60 days before the end date.</p>
        </div>
        {!form && <button className="btn ghost" onClick={() => setForm({ ...d, data_types: d.data_types || [] })}>{has ? 'Edit' : 'Add details'}</button>}
      </div>
      {error && <p className="error">{error}</p>}
      {form ? (
        <form className="form" onSubmit={save} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            {TEXT.map(([k, label, ph]) => (
              <label key={k}>{label}<input type={k === 'contact_email' ? 'email' : 'text'} value={form[k] || ''} placeholder={ph} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>
            ))}
            <label>Contract start<input type="date" value={form.contract_start || ''} onChange={(e) => setForm({ ...form, contract_start: e.target.value })} /></label>
            <label>Contract end<input type="date" value={form.contract_end || ''} onChange={(e) => setForm({ ...form, contract_end: e.target.value })} /></label>
          </div>
          <fieldset style={{ border: 0, padding: 0 }}>
            <legend className="small">Data they handle</legend>
            {DATA.map((t) => (
              <label key={t} className="small" style={{ display: 'inline-flex', gap: 6, marginRight: 14, alignItems: 'center' }}>
                <input type="checkbox" checked={(form.data_types || []).includes(t)} onChange={() => toggle(t)} />{t}
              </label>
            ))}
          </fieldset>
          <label>Notes<textarea rows={2} value={form.notes || ''} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>
          <div className="actions"><button type="button" className="btn ghost" onClick={() => setForm(null)}>Cancel</button><button className="btn primary">Save</button></div>
        </form>
      ) : has ? (
        <dl className="small" style={{ display: 'grid', gridTemplateColumns: 'minmax(140px, max-content) 1fr', gap: '6px 16px', margin: 0 }}>
          {TEXT.filter(([k]) => d[k]).map(([k, label]) => <Fragment key={k}><dt className="muted">{label}</dt><dd style={{ margin: 0 }}>{d[k]}</dd></Fragment>)}
          {d.data_types?.length > 0 && <><dt className="muted">Data they handle</dt><dd style={{ margin: 0 }}>{d.data_types.join(', ')}</dd></>}
          {(d.contract_start || d.contract_end) && <><dt className="muted">Contract</dt><dd style={{ margin: 0 }}>{d.contract_start || '?'} to {d.contract_end || 'open-ended'}</dd></>}
          {d.notes && <><dt className="muted">Notes</dt><dd style={{ margin: 0 }}>{d.notes}</dd></>}
        </dl>
      ) : <p className="muted small">No details yet.</p>}

      <h3 style={{ marginTop: 20 }}>Offboarding</h3>
      {!ob.started ? (
        <>
          <p className="muted small">When you stop using this vendor, work through a checklist so no access or data is left behind.</p>
          {isAdmin && <button className="btn ghost" onClick={start}>Start offboarding</button>}
        </>
      ) : (
        <>
          <p className="small">{ob.completed_at ? <span className="ok">Offboarding complete on {new Date(ob.completed_at).toLocaleDateString()}. You can now remove this company from your portfolio.</span>
            : `Started ${new Date(ob.started_at).toLocaleDateString()}. ${ob.items.filter((i) => i.done).length} of ${ob.items.length} done.`}</p>
          {ob.items.map((i) => (
            <label key={i.key} className="small" style={{ display: 'flex', gap: 8, alignItems: 'flex-start', padding: '6px 0' }}>
              <input type="checkbox" checked={i.done} onChange={(e) => tick(i.key, e.target.checked)} />
              <span>{i.label}{i.done && <span className="muted"> · {i.by}, {new Date(i.at).toLocaleDateString()}</span>}</span>
            </label>
          ))}
        </>
      )}
    </section>
  )
}
