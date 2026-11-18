import { useEffect, useState } from 'react'
import { Navigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

const LABELS = { account: 'User account', free_reports: 'Free-report requests', disputes: 'Disputes', opt_out_requests: 'Opt-out requests',
  questionnaires: 'Questionnaires sent to them', vendor_links: 'Vendor fix links sent to them', fix_owner: 'Named as fix owner',
  vendor_contact: 'Named as vendor contact', privacy_requests: 'Privacy requests' }
const STATUS = { new: 'New', in_progress: 'In progress', done: 'Done', rejected: 'Refused' }

export default function PrivacyRequests() {
  const { user } = useOutletContext()
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(null)
  const [found, setFound] = useState(null)
  const [form, setForm] = useState({ note: '', erase: false, suppress: false })
  const [error, setError] = useState(null)
  const load = () => api.listPrivacyRequests().then(setData).catch((e) => setError(e.message))
  useEffect(() => { if (user.role === 'owner') load() }, [])
  if (user.role !== 'owner') return <Navigate to="/" replace />

  async function show(r) {
    setOpen(r.id); setFound(null); setForm({ note: r.note || '', erase: r.kind === 'delete', suppress: r.kind === 'delete' || r.kind === 'object' })
    try { setFound(await api.lookupPrivacyRequest(r.id)) } catch (e) { setError(e.message) }
  }
  async function decide(id, status) {
    setError(null)
    try { await api.decidePrivacyRequest(id, { status, ...form }); setOpen(null); load() } catch (e) { setError(e.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Privacy requests</h1>
          <p className="muted">Requests from the public <a href="/privacy-request" target="_blank" rel="noreferrer">privacy request page</a>. Answer each within 30 days. Before acting, confirm the person controls the email address (reply to it and wait for an answer).</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      {data && (
        <section className="tiles">
          <div className="tile"><div className="tile-label">Open</div><div className="tile-value">{data.requests.filter((r) => ['new', 'in_progress'].includes(r.status)).length}</div></div>
          <div className="tile"><div className="tile-label">Overdue</div><div className={`tile-value ${data.requests.some((r) => r.overdue) ? 'warn' : ''}`}>{data.requests.filter((r) => r.overdue).length}</div></div>
          <div className="tile"><div className="tile-label">Suppressed addresses</div><div className="tile-value">{data.suppressed}</div><div className="muted small">Stored only as hashes</div></div>
        </section>
      )}
      <section className="card table-card">
        {!data ? <p className="muted pad">Loading…</p> : data.requests.length === 0 ? <p className="muted pad">No requests yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Received</th><th>Request</th><th>From</th><th>Due</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {data.requests.map((r) => (
                  <tr key={r.id} className="static">
                    <td className="small">{new Date(r.created_at).toLocaleDateString()}</td>
                    <td className="small"><strong>{r.kind_label}</strong>{r.details && <div className="muted">{r.details}</div>}
                      {open === r.id && (
                        <div style={{ marginTop: 10 }}>
                          {!found ? <p className="muted">Looking up…</p> : (
                            <>
                              <p><strong>Where this address appears</strong></p>
                              <ul>{Object.entries(LABELS).map(([k, label]) => {
                                const v = found[k]; const n = Array.isArray(v) ? v.length : v
                                return n ? <li key={k}>{label}: {Array.isArray(v) ? v.map((a) => `${a.name} at ${a.organisation} (${a.role})`).join('; ') : n}</li> : null
                              })}</ul>
                              {found.account?.length > 0 && <p className="muted">They have a user account. Accounts are deleted by the user in Account settings, or by their organisation's admin in Team.</p>}
                              {found.suppressed && <p className="muted">Already on the suppression list.</p>}
                            </>
                          )}
                          <label className="small" style={{ display: 'flex', gap: 6 }}><input type="checkbox" checked={form.erase} onChange={(e) => setForm({ ...form, erase: e.target.checked })} />Erase this address everywhere above (not accounts or the audit log)</label>
                          <label className="small" style={{ display: 'flex', gap: 6 }}><input type="checkbox" checked={form.suppress} onChange={(e) => setForm({ ...form, suppress: e.target.checked })} />Add to the suppression list (never email or store it again)</label>
                          <textarea rows={2} value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="Note (required when refusing)" style={{ width: '100%', marginTop: 6 }} />
                          <div className="actions" style={{ justifyContent: 'flex-start' }}>
                            <button className="btn ghost" onClick={() => decide(r.id, 'in_progress')}>Mark in progress</button>
                            <button className="btn primary" onClick={() => decide(r.id, 'done')}>Mark done</button>
                            <button className="btn ghost" onClick={() => decide(r.id, 'rejected')}>Refuse</button>
                          </div>
                        </div>
                      )}
                    </td>
                    <td className="small">{r.name && <div>{r.name}</div>}<span className="mono">{r.email}</span></td>
                    <td className="small"><span className={r.overdue ? 'error' : ''}>{r.due}</span></td>
                    <td className="small">{STATUS[r.status]}{r.result?.erased && <div className="muted">erased</div>}</td>
                    <td>{open === r.id ? <button className="btn ghost" onClick={() => setOpen(null)}>Close</button> : <button className="btn ghost" onClick={() => show(r)}>Handle</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {data && <p className="muted small">Automatic deletion runs daily: {Object.entries(data.retention_days).map(([k, d]) => `${k.replace(/_/g, ' ')} after ${d} days`).join(', ')}.</p>}
    </>
  )
}
