import { useEffect, useState } from 'react'
import { api } from '../api.js'

const LABEL = { fixed: 'Fixed', in_progress: 'Working on it', not_ours: 'Not our system', accepted_risk: 'Accepted risk' }

export default function VendorShares({ entityId, entityName, user }) {
  const [rows, setRows] = useState([])
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(null)
  const [openId, setOpenId] = useState(null)
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const load = () => api.listVendorShares(entityId).then(setRows).catch(() => {})
  useEffect(() => { load() }, [entityId])

  function copy(s) {
    navigator.clipboard?.writeText(window.location.origin + s.link_path).then(() => setCopied(s.id)).catch(() => setCopied(null))
  }
  async function create(e) {
    e.preventDefault(); setError(null)
    try { const s = await api.createVendorShare(entityId, form); setForm(null); await load(); copy(s) } catch (err) { setError(err.message) }
  }
  async function revoke(id) { await api.revokeVendorShare(id).catch(() => {}); load() }

  return (
    <section className="card table-card">
      <div className="section-head">
        <div>
          <h2>Ask {entityName} to fix issues</h2>
          <p className="muted small">Send a private link. The vendor sees its issues with fix advice, replies to each one and can ask for a rescan to prove a fix. No account needed.</p>
        </div>
        {isAdmin && !form && <button className="btn ghost" onClick={() => setForm({ recipient_email: '', recipient_name: '', message: '' })}>Share issues with vendor</button>}
      </div>
      {form && (
        <form className="form pad" onSubmit={create} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Vendor contact email<input type="email" required value={form.recipient_email} onChange={(e) => setForm({ ...form, recipient_email: e.target.value })} /></label>
            <label>Contact name<input value={form.recipient_name} onChange={(e) => setForm({ ...form, recipient_name: e.target.value })} placeholder="Optional" /></label>
          </div>
          <label>Message<textarea rows={2} value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} placeholder="Optional, e.g. Please fix the high-severity items by month end" /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions">
            <button type="button" className="btn ghost" onClick={() => setForm(null)}>Cancel</button>
            <button className="btn primary">Create link</button>
          </div>
          <p className="muted small">You get a link to send. It is also emailed when email is set up. Links last 30 days.</p>
        </form>
      )}
      {rows.length === 0 && !form ? <p className="muted pad">No links shared yet.</p> : rows.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Shared with</th><th>Status</th><th>Replies</th><th></th></tr></thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} className="static">
                  <td className="small">{s.recipient_name && <div>{s.recipient_name}</div>}{s.recipient_email}
                    <div className="muted">{new Date(s.created_at).toLocaleDateString()}{s.last_viewed_at ? ` · opened ${new Date(s.last_viewed_at).toLocaleDateString()}` : ' · not opened yet'}</div></td>
                  <td><span className="role">{s.state}</span></td>
                  <td className="small">
                    {s.replies === 0 ? <span className="muted">None yet</span> : Object.entries(s.by_status).filter(([, n]) => n).map(([k, n]) => <div key={k}>{n} {LABEL[k].toLowerCase()}</div>)}
                    {s.replies > 0 && <button className="btn ghost tiny" onClick={() => setOpenId(openId === s.id ? null : s.id)}>{openId === s.id ? 'Hide' : 'Show replies'}</button>}
                    {openId === s.id && s.findings.filter((f) => f.response).map((f) => (
                      <div key={f.id} className="dns-box">
                        <div className="strong">{f.title}</div>
                        <div>{LABEL[f.response.status]}{f.status !== 'open' ? ' · confirmed by our latest scan' : f.response.status === 'fixed' ? ' · not yet confirmed by a scan' : ''}</div>
                        {f.response.comment && <div className="muted">“{f.response.comment}”</div>}
                      </div>
                    ))}
                  </td>
                  <td>
                    {s.state === 'active' && isAdmin && (
                      <div className="row-actions">
                        <button className="btn ghost tiny" onClick={() => copy(s)}>{copied === s.id ? 'Link copied' : 'Copy link'}</button>
                        <button className="btn ghost tiny" onClick={() => revoke(s.id)}>Withdraw</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
