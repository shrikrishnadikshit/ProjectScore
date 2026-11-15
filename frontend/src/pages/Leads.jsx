import { useEffect, useState } from 'react'
import { Link, Navigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'
import { GradeBadge } from '../components/Grade.jsx'

export default function Leads() {
  const { user } = useOutletContext()
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { if (user.role === 'owner') api.listLeads().then(setRows).catch((e) => setError(e.message)) }, [])
  if (user.role !== 'owner') return <Navigate to="/" replace />

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Free report leads</h1>
          <p className="muted">People who requested a free rating from the <a href="/free-report" target="_blank" rel="noreferrer">free report page</a>. They saw a summary only, without hostnames or IP addresses.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      <div className="card table-card">
        {rows && rows.length === 0 ? <p className="muted pad" style={{ paddingTop: 20 }}>No requests yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Requested</th><th>Contact</th><th>Domain</th><th>Rating</th><th>Status</th></tr></thead>
              <tbody>
                {(rows ?? []).map((r) => (
                  <tr key={r.id} className="static">
                    <td className="small muted">{new Date(r.created_at).toLocaleString()}</td>
                    <td className="small">{r.name || <span className="muted">No name</span>}<div><a href={`mailto:${r.contact_email}`}>{r.contact_email}</a></div>{r.organisation && <div className="muted">{r.organisation}</div>}</td>
                    <td className="mono small">{r.domain}</td>
                    <td>{r.grade ? <span className="row-actions"><GradeBadge grade={r.grade} size="sm" /> {r.score}</span> : <span className="muted">None</span>}</td>
                    <td><span className="role">{r.status}</span></td>
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
