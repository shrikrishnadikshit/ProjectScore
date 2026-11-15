import { useEffect, useState } from 'react'
import { Link, Navigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

export default function Disputes() {
  const { user } = useOutletContext()
  const [rows, setRows] = useState(null)
  const [notes, setNotes] = useState({})
  const [error, setError] = useState(null)
  const load = () => api.listDisputes().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { if (user.role === 'owner') load() }, [])

  if (user.role !== 'owner') return <Navigate to="/" replace />

  async function decide(id, status) {
    setError(null)
    try { await api.decideDispute(id, status, notes[id] || null); load() } catch (e) { setError(e.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Disputes</h1>
          <p className="muted">Challenges to findings from customers and from rated companies. Accepting a dispute on a finding marks it as a false positive, stops it coming back on later scans, and recalculates the score straight away. Public disputes have no linked finding, so check the company and fix the finding by hand.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      <div className="card table-card">
        {rows && rows.length === 0 ? <p className="muted pad" style={{ paddingTop: 20 }}>No disputes yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Company and finding</th><th>From</th><th>Reason</th><th>Status</th><th>Decision</th></tr></thead>
              <tbody>
                {(rows ?? []).map((d) => (
                  <tr key={d.id} className="static">
                    <td className="small">
                      {d.entity ? <Link to={`/entities/${d.entity.id}`}>{d.entity.name}</Link> : <span className="mono">{d.domain}</span>}
                      {d.finding && <div><span className={`sev sev-${d.finding.severity}`}>{d.finding.severity}</span> {d.finding.title}<div className="mono muted">{d.finding.asset}</div></div>}
                    </td>
                    <td className="small">{d.submitted_by}<div className="muted">{d.organisation}</div><div className="muted">{new Date(d.created_at).toLocaleDateString()}</div></td>
                    <td className="small" style={{ maxWidth: 320 }}>{d.reason}</td>
                    <td><span className="role">{d.status}</span>{d.reviewer_note && <div className="muted small">{d.reviewer_note}</div>}</td>
                    <td>
                      <input className="small" placeholder="Note (optional)" value={notes[d.id] ?? ''} onChange={(e) => setNotes({ ...notes, [d.id]: e.target.value })} />
                      <div className="row-actions" style={{ marginTop: 6 }}>
                        {d.status !== 'accepted' && <button className="btn ghost tiny" onClick={() => decide(d.id, 'accepted')}>Accept</button>}
                        {d.status !== 'rejected' && <button className="btn ghost tiny" onClick={() => decide(d.id, 'rejected')}>Reject</button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
