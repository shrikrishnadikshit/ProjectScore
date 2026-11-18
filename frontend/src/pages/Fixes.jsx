import { useEffect, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

const STATUS = { open: 'Open', in_progress: 'In progress', fixed: 'Fixed, waiting for rescan', verified: 'Verified by rescan', accepted: 'Risk accepted', wont_fix: "Won't fix" }

export default function Fixes() {
  const { user } = useOutletContext()
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const [mine, setMine] = useState(false)
  const [all, setAll] = useState(false)
  const [data, setData] = useState(null)
  const [acc, setAcc] = useState([])
  const [error, setError] = useState(null)
  const load = () => {
    api.listTasks(`?mine=${mine}&open_only=${!all}`).then(setData).catch((e) => setError(e.message))
    api.listAcceptances().then(setAcc).catch(() => {})
  }
  useEffect(load, [mine, all])
  if (error && !data) return <div className="card error">{error}</div>
  if (!data) return <div className="muted">Loading…</div>
  const st = data.stats
  const act = (fn) => async () => { setError(null); try { await fn(); load() } catch (e) { setError(e.message) } }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Fix tracking</h1>
          <p className="muted">Issues assigned to someone with a due date. A task closes itself when a rescan no longer sees the issue. Deadlines per severity are set in Settings. Create tasks from the "How to improve this score" list on any company.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      <section className="tiles">
        <div className="tile"><div className="tile-label">Open</div><div className="tile-value">{st.open}</div></div>
        <div className="tile"><div className="tile-label">Overdue</div><div className={`tile-value ${st.overdue ? 'warn' : ''}`}>{st.overdue}</div></div>
        <div className="tile"><div className="tile-label">Average time to fix</div><div className="tile-value">{st.mttr_days != null ? `${st.mttr_days} days` : '—'}</div><div className="muted small">{st.verified} verified fixes</div></div>
        <div className="tile"><div className="tile-label">Fixed on time</div><div className="tile-value">{st.on_time_pct != null ? `${st.on_time_pct}%` : '—'}</div></div>
      </section>
      <section className="card table-card">
        <div className="table-tools">
          <label className="check small"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />Only mine</label>
          <label className="check small"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />Include closed</label>
        </div>
        {data.tasks.length === 0 ? <p className="muted pad">No tasks here yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Company and issue</th><th>Owner</th><th>Due</th><th>Status</th></tr></thead>
              <tbody>{data.tasks.map((t) => (
                <tr key={t.id} className="static">
                  <td><Link to={`/entities/${t.entity_id}`} className="row-title">{t.company}</Link><div className="small"><span className={`sev sev-${t.severity}`}>{t.severity}</span> {t.title}</div>{t.note && <div className="small muted">{t.note}</div>}</td>
                  <td className="small">{t.assignee || <span className="muted">Unassigned</span>}</td>
                  <td className="small"><span className={t.overdue ? 'error' : ''}>{t.due}{t.overdue ? ' (overdue)' : ''}</span></td>
                  <td className="small">
                    {['verified', 'accepted', 'wont_fix'].includes(t.status) ? STATUS[t.status] : (
                      <select value={t.status} onChange={(e) => act(() => api.updateTask(t.id, { status: e.target.value }))()}>
                        {['open', 'in_progress', 'fixed', ...(isAdmin ? ['wont_fix'] : [])].map((s) => <option key={s} value={s}>{STATUS[s]}</option>)}
                      </select>
                    )}
                  </td>
                </tr>))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="card table-card">
        <h2>Risk acceptances</h2>
        {acc.length === 0 ? <p className="muted pad">None. Request one from a company's fix list when a risk will not be fixed for now.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Company and scope</th><th>Why</th><th>Expires</th><th>Status</th></tr></thead>
              <tbody>{acc.map((a) => (
                <tr key={a.id} className="static">
                  <td><Link to={`/entities/${a.entity_id}`} className="row-title">{a.company}</Link><div className="small mono">{a.scope}</div></td>
                  <td className="small">{a.reason}{a.controls && <div className="muted">Controls: {a.controls}</div>}<div className="muted">Requested by {a.requested_by}{a.approver ? `, decided by ${a.approver}${a.self_approved ? ' (own request)' : ''}` : ''}</div></td>
                  <td className="small">{a.expires_on}</td>
                  <td className="small">{a.status}
                    {isAdmin && a.status === 'pending' && <div className="actions" style={{ justifyContent: 'flex-start' }}>
                      <button className="btn ghost" onClick={act(() => api.decideAcceptance(a.id, true))}>Approve</button>
                      <button className="btn ghost" onClick={act(() => api.decideAcceptance(a.id, false))}>Reject</button></div>}
                    {isAdmin && a.status === 'approved' && <div><button className="link-btn" onClick={act(() => api.revokeAcceptance(a.id))}>Revoke</button></div>}
                  </td>
                </tr>))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
