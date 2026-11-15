import { useEffect, useState } from 'react'
import { api } from '../api.js'

const STATUS = { valid: 'Valid', expiring: 'Expiring soon', expired: 'Expired', no_expiry: 'No expiry date' }
const EMPTY = { kind: 'iso27001', reference: '', issuer: '', scope: '', issued_on: '', expires_on: '', exceptions: '', note: '' }

export default function Certificates({ entityId }) {
  const [data, setData] = useState(null)
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.listCertificates(entityId).then(setData).catch(() => {})
  useEffect(() => { load() }, [entityId])
  if (!data) return null

  async function save(e) {
    e.preventDefault(); setError(null)
    const body = { ...form, issued_on: form.issued_on || null, expires_on: form.expires_on || null,
      exceptions: form.exceptions === '' ? null : Number(form.exceptions) }
    try {
      if (form.id) await api.updateCertificate(form.id, body); else await api.addCertificate(entityId, body)
      setForm(null); load()
    } catch (err) { setError(err.message) }
  }
  async function remove(id) { await api.deleteCertificate(id).catch(() => {}); load() }
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  return (
    <section className="card table-card">
      <div className="section-head">
        <div>
          <h2>Certificates and audit reports</h2>
          <p className="muted small">Record the ISO 27001, SOC 2 or other evidence this vendor has shared. You get a reminder 30 days before each one expires.</p>
        </div>
        {!form && <button className="btn ghost" onClick={() => setForm(EMPTY)}>Add certificate</button>}
      </div>
      {data.warnings.map((w, i) => <div key={i} className="banner" style={{ margin: '0 20px 12px' }}>{w}</div>)}
      {form && (
        <form className="form pad" onSubmit={save} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Type<select value={form.kind} onChange={set('kind')}>{Object.entries(data.kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            <label>Certificate number or report name<input value={form.reference ?? ''} onChange={set('reference')} /></label>
          </div>
          <div className="form-row">
            <label>Issued by (certification body or audit firm)<input value={form.issuer ?? ''} onChange={set('issuer')} /></label>
            <label>Exceptions or nonconformities<input type="number" min="0" value={form.exceptions ?? ''} onChange={set('exceptions')} placeholder="Optional" /></label>
          </div>
          <div className="form-row">
            <label>Issued on<input type="date" value={form.issued_on ?? ''} onChange={set('issued_on')} /></label>
            <label>Expires on<input type="date" value={form.expires_on ?? ''} onChange={set('expires_on')} /></label>
          </div>
          <label>Scope<input value={form.scope ?? ''} onChange={set('scope')} placeholder="e.g. Cloud hosting operations, Bengaluru and Pune" /></label>
          <label>Note<input value={form.note ?? ''} onChange={set('note')} /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button type="button" className="btn ghost" onClick={() => setForm(null)}>Cancel</button><button className="btn primary">Save</button></div>
        </form>
      )}
      {data.certificates.length === 0 && !form ? <p className="muted pad">None recorded.</p> : data.certificates.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Certificate</th><th>Issued by</th><th>Expires</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {data.certificates.map((c) => (
                <tr key={c.id} className="static">
                  <td><div className="strong">{c.kind_label}</div>{c.reference && <div className="small muted">{c.reference}</div>}{c.scope && <div className="small muted">Scope: {c.scope}</div>}{c.exceptions != null && <div className="small">{c.exceptions} exception{c.exceptions === 1 ? '' : 's'}</div>}</td>
                  <td className="small">{c.issuer || '—'}</td>
                  <td className="small">{c.expires_on ? new Date(c.expires_on).toLocaleDateString() : '—'}{c.days_left != null && c.days_left >= 0 && <div className="muted">{c.days_left} days left</div>}</td>
                  <td><span className={`sev sev-${c.status === 'expired' ? 'high' : c.status === 'expiring' ? 'medium' : 'info'}`}>{STATUS[c.status]}</span></td>
                  <td><div className="row-actions"><button className="btn ghost tiny" onClick={() => setForm({ ...EMPTY, ...Object.fromEntries(Object.entries(c).map(([k, v]) => [k, v ?? ''])) })}>Edit</button><button className="btn ghost tiny" onClick={() => remove(c.id)}>Remove</button></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
