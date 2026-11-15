import { useEffect, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

const STATUS = { new: 'New', in_progress: 'In progress', done: 'Done', declined: 'Declined' }

export default function Advisory() {
  const { user } = useOutletContext()
  const isOwner = user.role === 'owner'
  const [rows, setRows] = useState(null)
  const [notes, setNotes] = useState({})
  const [error, setError] = useState(null)
  const load = () => api.listAdvisory().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  async function update(r, status) {
    try { await api.updateAdvisory(r.id, status, notes[r.id] ?? r.owner_note); load() } catch (e) { setError(e.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Advisory and remediation help</h1>
          <p className="muted">{isOwner ? 'Requests from customers for expert help. Reply with a note and keep the status up to date; customers see both.' : 'Your requests for expert help. Use "Get expert help" on any company page to ask for more.'}</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      {rows && rows.length === 0 && <div className="card"><p className="muted">No requests yet.</p></div>}
      <div className="alert-list">
        {(rows ?? []).map((r) => (
          <div key={r.id} className="card">
            <div className="alert-head">
              <span className="role">{STATUS[r.status]}</span>
              <span className="strong">{r.service_label}</span>
              {r.entity && <Link to={`/entities/${r.entity.id}`}>{r.entity.name}</Link>}
              <span className="muted small alert-time">{new Date(r.created_at).toLocaleString()}</span>
            </div>
            <div className="small muted">{r.organisation} · {r.requested_by}{r.preferred_contact ? ` · contact: ${r.preferred_contact}` : ''}</div>
            {r.message && <p className="small">{r.message}</p>}
            {r.finding_codes.length > 0 && <div className="chips">{r.finding_codes.map((c) => <span key={c} className="mono small asset">{c}</span>)}</div>}
            {isOwner ? (
              <div className="form" style={{ maxWidth: 'none', marginTop: 10 }}>
                <label>Reply to the customer<textarea rows={2} value={notes[r.id] ?? r.owner_note ?? ''} onChange={(e) => setNotes({ ...notes, [r.id]: e.target.value })} /></label>
                <div className="row-actions">
                  {['in_progress', 'done', 'declined'].map((s) => <button key={s} className="btn ghost tiny" onClick={() => update(r, s)}>Mark {STATUS[s].toLowerCase()}</button>)}
                </div>
              </div>
            ) : r.owner_note && <p className="small"><strong>Our reply:</strong> {r.owner_note}</p>}
          </div>
        ))}
      </div>
    </>
  )
}
