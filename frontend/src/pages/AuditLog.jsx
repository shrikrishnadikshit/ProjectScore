import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function AuditLog() {
  const [days, setDays] = useState(30)
  const [q, setQ] = useState('')
  const [data, setData] = useState(null)
  const [check, setCheck] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { const t = setTimeout(() => api.auditLog(days, q).then(setData).catch((e) => setError(e.message)), 250); return () => clearTimeout(t) }, [days, q])
  if (error) return <div className="card error">{error}</div>
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted">Every change made in your organisation, who made it and when, plus sign-ins and failed sign-in attempts. Entries are chained with hashes, so any later edit or deletion is detectable.</p>
        </div>
      </div>
      <section className="card table-card">
        <div className="table-tools">
          <input placeholder="Search user, action or page" value={q} onChange={(e) => setQ(e.target.value)} />
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90, 365].map((d) => <option key={d} value={d}>Last {d} days</option>)}</select>
          <a className="btn ghost" href={`/api/audit/export?days=${days}`} download>Download CSV</a>
          <button className="btn ghost" onClick={() => api.auditVerify().then(setCheck)}>Check integrity</button>
        </div>
        {check && <p className={`small pad ${check.ok ? 'ok' : 'error'}`}>{check.ok ? `Intact: all ${check.checked} entries match their hashes.` : `Broken at entry ${check.broken_at}: an entry was changed or removed after it was written.`}</p>}
        {!data ? <p className="muted pad">Loading…</p> : data.events.length === 0 ? <p className="muted pad">Nothing recorded in this period.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>When</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr></thead>
              <tbody>{data.events.map((e) => (
                <tr key={e.id} className="static">
                  <td className="small">{new Date(e.at).toLocaleString()}</td>
                  <td className="small">{e.actor || '—'}</td>
                  <td className="small">{e.action.replace(/_/g, ' ')}</td>
                  <td className="small mono">{e.target}{e.status >= 400 ? <span className="error"> ({e.status})</span> : ''}</td>
                  <td className="small mono">{e.ip}</td>
                </tr>))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > data.events.length && <p className="muted small pad">Showing the latest {data.events.length} of {data.total}. Download the CSV for all of them.</p>}
      </section>
    </>
  )
}
