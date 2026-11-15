import { useEffect, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

export default function Alerts() {
  const { refreshAlerts } = useOutletContext()
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.listAlerts().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  async function readAll() {
    await api.readAllAlerts()
    await load()
    refreshAlerts()
  }
  async function open(a) {
    if (!a.read) { await api.readAlert(a.id).catch(() => {}); refreshAlerts() }
  }

  const unread = rows?.filter((a) => !a.read).length ?? 0
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="muted">Raised when a company in your portfolio drops a grade, its score falls by 20 points or more, or a new critical or high-severity issue appears.</p>
        </div>
        {unread > 0 && <button className="btn ghost" onClick={readAll}>Mark all as read</button>}
      </div>
      {error && <div className="banner error">{error}</div>}
      {rows && rows.length === 0 && <div className="card"><p className="muted">No alerts yet. Companies are rescanned every week, and you will see changes here.</p></div>}
      <div className="alert-list">
        {(rows ?? []).map((a) => (
          <div key={a.id} className={`card alert-item ${a.read ? 'read' : ''} alert-${a.severity}`}>
            <div className="alert-head">
              {!a.read && <span className="dot" aria-label="Unread" />}
              <Link to={a.entity_id ? `/entities/${a.entity_id}` : a.kind?.startsWith('reputation') ? '/reputation' : '/alerts'} onClick={() => open(a)} className="strong">{a.title}</Link>
              <span className="muted small alert-time">{new Date(a.created_at).toLocaleString()}</span>
            </div>
            {a.detail && <pre className="alert-detail small">{a.detail}</pre>}
          </div>
        ))}
      </div>
    </>
  )
}
