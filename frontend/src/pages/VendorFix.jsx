import PublicFooter from '../components/PublicFooter.jsx'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../api.js'

export default function VendorFix() {
  const { token } = useParams()
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [drafts, setDrafts] = useState({})
  const [saved, setSaved] = useState(null)
  const [rescan, setRescan] = useState(null)
  const load = () => api.publicVendorShare(token).then(setData).catch((e) => setError(e.message))
  useEffect(() => { load() }, [token])

  if (error && !data) return <div className="public"><div className="card error">This link is not valid, has expired or was withdrawn. Please ask the sender for a new one.</div></div>
  if (!data) return <div className="public"><p className="muted">Loading…</p></div>

  async function reply(f) {
    const d = drafts[f.id] || {}
    const status = d.status || f.response?.status
    if (!status) return
    try {
      await api.replyVendorShare(token, f.id, status, d.comment ?? f.response?.comment ?? '')
      setSaved(f.id); await load()
    } catch (e) { setError(e.message) }
  }
  async function askRescan() {
    try { await api.rescanVendorShare(token); setRescan('Rescan started. Results usually update within a few minutes; reload this page to see them.'); setData({ ...data, can_rescan: false }) } catch (e) { setRescan(e.message) }
  }
  const open = data.findings.filter((f) => f.status === 'open')
  const closed = data.findings.filter((f) => f.status !== 'open')

  return (
    <div className="public">
      <span className="brand"><span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg></span>ProjectScore</span>
      <h1>Security issues found on {data.company}</h1>
      <p>{data.requested_by} monitors the security of {data.domain} from the outside and has asked for your help fixing what we found. We only looked at publicly visible systems.{data.grade && <> The current rating is <b>{data.score} ({data.grade})</b>{data.scanned_at && `, from a scan on ${new Date(data.scanned_at).toLocaleDateString()}`}.</>}</p>
      {data.message && <div className="card"><div className="muted small">Message from {data.requested_by}</div><p>{data.message}</p></div>}
      <div className="card">
        <p className="small">For each issue, choose a reply and add a comment if it helps. When you have fixed something, ask for a rescan: fixed issues disappear and the rating updates.</p>
        <button className="btn primary" onClick={askRescan} disabled={!data.can_rescan}>Rescan now</button>
        {!data.can_rescan && !rescan && <span className="muted small"> A rescan can be requested every 6 hours.</span>}
        {rescan && <p className="small">{rescan}</p>}
      </div>
      {open.length === 0 && <div className="card"><p className="strong">No open issues. Thank you.</p></div>}
      {open.map((f) => {
        const d = drafts[f.id] || {}
        const current = d.status || f.response?.status || ''
        return (
          <section key={f.id} className="card">
            <div className="section-head" style={{ marginBottom: 4 }}>
              <h2 style={{ margin: 0 }}>{f.title}</h2>
              <span className={`sev sev-${f.severity}`}>{f.severity}</span>
            </div>
            <div className="mono small muted">{f.asset}</div>
            {f.why && <p className="small">{f.why}</p>}
            {f.fix?.length > 0 && <><div className="small strong">How to fix</div><ol className="small">{f.fix.map((s, i) => <li key={i}>{s}</li>)}</ol></>}
            <div className="qa-options">
              {Object.entries(data.statuses).map(([k, label]) => (
                <label key={k} className={`qa-opt ${current === k ? 'on' : ''}`}>
                  <input type="radio" name={`s${f.id}`} checked={current === k} onChange={() => setDrafts({ ...drafts, [f.id]: { ...d, status: k } })} />{label}
                </label>
              ))}
            </div>
            <input className="qa-comment-input small" placeholder="Comment (optional)" value={d.comment ?? f.response?.comment ?? ''} onChange={(e) => setDrafts({ ...drafts, [f.id]: { ...d, comment: e.target.value } })} />
            <div className="actions" style={{ marginTop: 8 }}>
              <button className="btn ghost small-btn" onClick={() => reply(f)} disabled={!current}>Send reply</button>
              {saved === f.id && <span className="ok small">Reply sent to {data.requested_by}.</span>}
              {f.response && saved !== f.id && <span className="muted small">You replied {new Date(f.response.at).toLocaleDateString()}</span>}
            </div>
          </section>
        )
      })}
      {closed.length > 0 && (
        <section className="card">
          <h2>Confirmed fixed</h2>
          {closed.map((f) => <div key={f.id} className="small">✓ {f.title} <span className="mono muted">{f.asset}</span></div>)}
        </section>
      )}
      {error && <div className="banner error">{error}</div>}
      <PublicFooter />
    </div>
  )
}
