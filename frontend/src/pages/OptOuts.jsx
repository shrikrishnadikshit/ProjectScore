import { useEffect, useState } from 'react'
import { Navigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

export default function OptOuts() {
  const { user } = useOutletContext()
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.listOptOuts().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { if (user.role === 'owner') load() }, [])

  if (user.role !== 'owner') return <Navigate to="/" replace />

  async function decide(id, status) {
    try { await api.decideOptOut(id, status); load() } catch (e) { setError(e.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Opt-out requests</h1>
          <p className="muted">Requests from the public <a href="/scanner" target="_blank" rel="noreferrer">scanner page</a>. Approving one stops all scanning of that domain and its subdomains. Check the requester's email belongs to the domain before approving.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      <div className="card table-card">
        {rows && rows.length === 0 ? <p className="muted pad" style={{ paddingTop: 20 }}>No requests yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Domain</th><th>Requested by</th><th>Message</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {(rows ?? []).map((r) => (
                  <tr key={r.id} className="static">
                    <td className="mono small">{r.domain}</td>
                    <td className="small">{r.contact_email}{r.organisation && <div className="muted">{r.organisation}</div>}<div className="muted">{new Date(r.created_at).toLocaleDateString()}</div></td>
                    <td className="small">{r.reason || <span className="muted">None</span>}</td>
                    <td><span className="role">{r.status}</span></td>
                    <td>
                      <div className="row-actions">
                        {r.status !== 'approved' && <button className="btn ghost tiny" onClick={() => decide(r.id, 'approved')}>Approve</button>}
                        {r.status !== 'rejected' && <button className="btn ghost tiny" onClick={() => decide(r.id, 'rejected')}>Reject</button>}
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
