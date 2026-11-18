import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

const EFFORT = { quick: 'Quick fix', moderate: 'Moderate effort', project: 'Project' }

export default function FixPlan({ entityId, version }) {
  const [plan, setPlan] = useState(null)
  const [open, setOpen] = useState(null)
  const [picked, setPicked] = useState(new Set())
  const [helpForm, setHelpForm] = useState(null)
  const [services, setServices] = useState([])
  const [sent, setSent] = useState(false)
  const [error, setError] = useState(null)
  const [tasks, setTasks] = useState({})
  const [people, setPeople] = useState([])
  const [trackForm, setTrackForm] = useState(null)
  const [acceptForm, setAcceptForm] = useState(null)
  const [flash, setFlash] = useState(null)
  const loadTasks = () => api.listTasks(`?entity_id=${entityId}&open_only=false`).then((d) => setTasks(Object.fromEntries(d.tasks.map((t) => [t.code, t])))).catch(() => {})
  useEffect(() => { loadTasks(); api.colleagues().then(setPeople).catch(() => {}) }, [entityId, version])
  async function track(e) {
    e.preventDefault(); setError(null)
    try {
      await api.createTask({ entity_id: Number(entityId), code: trackForm.code, assignee_id: trackForm.who && !trackForm.who.includes('@') ? Number(trackForm.who) : null,
        assignee_email: trackForm.who?.includes('@') ? trackForm.who : (trackForm.email || null), note: trackForm.note || null })
      setTrackForm(null); loadTasks()
    } catch (err) { setError(err.message) }
  }
  async function accept(e) {
    e.preventDefault(); setError(null)
    try { await api.requestAcceptance({ entity_id: Number(entityId), ...acceptForm }); setAcceptForm(null); setFlash('Risk acceptance requested. An admin approves it on the Fixes page.') } catch (err) { setError(err.message) }
  }
  const [jira, setJira] = useState(false)
  const [tickets, setTickets] = useState({})
  useEffect(() => { api.listIntegrations().then((d) => setJira(d.jira.connected && d.jira.enabled !== false)).catch(() => {}) }, [])
  async function ticket(code) {
    setTickets({ ...tickets, [code]: { busy: true } })
    try { const r = await api.createJiraIssue(entityId, code); setTickets((t) => ({ ...t, [code]: r })) }
    catch (e) { setTickets((t) => ({ ...t, [code]: { error: e.message } })) }
  }
  useEffect(() => { api.remediationPlan(entityId).then(setPlan).catch(() => setPlan(null)) }, [entityId, version])
  useEffect(() => { if (helpForm) api.advisoryServices().then(setServices) }, [helpForm != null])
  if (!plan?.items?.length) return null

  const toggle = (code) => { const n = new Set(picked); n.has(code) ? n.delete(code) : n.add(code); setPicked(n) }
  async function requestHelp(e) {
    e.preventDefault()
    setError(null)
    try {
      await api.requestAdvisory(entityId, { ...helpForm, finding_codes: [...picked] })
      setHelpForm(null); setSent(true); setPicked(new Set())
    } catch (err) { setError(err.message) }
  }

  return (
    <section className="card">
      <div className="section-head">
        <h2>How to improve this score</h2>
        {!helpForm && <button className="btn primary" onClick={() => { setSent(false); setHelpForm({ service: 'fix_guidance', message: '', preferred_contact: '' }) }}>Get expert help{picked.size ? ` (${picked.size} selected)` : ''}</button>}
      </div>
      <div className="stats">
        <div><div className="stat">{plan.current}</div><div className="muted small">score now</div></div>
        <div><div className="stat">{plan.after_quick_fixes}</div><div className="muted small">after the quick fixes</div></div>
        <div><div className="stat">{plan.after_all_fixes}</div><div className="muted small">after fixing everything listed</div></div>
      </div>
      {flash && <div className="banner">{flash}</div>}
      {sent && <div className="banner">Request sent. Our team will contact you, usually within one working day. Track it on the <Link to="/advisory">Advisory</Link> page.</div>}
      {helpForm && (
        <form className="form" onSubmit={requestHelp} style={{ maxWidth: 'none' }}>
          <label>What do you need?
            <select value={helpForm.service} onChange={(e) => setHelpForm({ ...helpForm, service: e.target.value })}>
              {services.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </label>
          <p className="muted small">{picked.size ? `${picked.size} issue type${picked.size > 1 ? 's' : ''} selected below will be included.` : 'Tip: tick issues below to include them in the request.'}</p>
          <div className="form-row">
            <label>Anything we should know<textarea rows={2} value={helpForm.message} onChange={(e) => setHelpForm({ ...helpForm, message: e.target.value })} /></label>
            <label>Best way to reach you<input value={helpForm.preferred_contact} onChange={(e) => setHelpForm({ ...helpForm, preferred_contact: e.target.value })} placeholder="Phone or email (optional)" /></label>
          </div>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button type="button" className="btn ghost" onClick={() => setHelpForm(null)}>Cancel</button><button className="btn primary">Send request</button></div>
        </form>
      )}
      <div className="fw-list">
        {plan.items.map((it) => (
          <div key={it.code} className="fw-row">
            <div className="plan-head">
              <input type="checkbox" aria-label={`Select ${it.title}`} checked={picked.has(it.code)} onChange={() => toggle(it.code)} />
              <button className="fw-head plan-btn" onClick={() => setOpen(open === it.code ? null : it.code)} aria-expanded={open === it.code}>
                <span className={`sev sev-${it.severity}`}>{it.severity}</span>
                <span className="small">{it.title}{it.assets.length > 1 ? ` (${it.assets.length} assets)` : ''}</span>
                <span className="small plan-meta"><span className="muted">{EFFORT[it.effort]}</span> {it.points > 0 ? <strong className="ok">+{it.points} pts</strong> : <span className="muted">no score change</span>}</span>
              </button>
            </div>
            {open === it.code && (
              <div className="plan-body small">
                <p><strong>Why it matters:</strong> {it.why}</p>
                <p><strong>How to fix</strong> <span className="muted">(usually {it.owner})</span>:</p>
                <ol>{it.fix.map((s, i) => <li key={i}>{s}</li>)}</ol>
                {it.certin && <p className="small">Guidance: <a href={it.certin.url} target="_blank" rel="noreferrer">{it.certin.label}</a></p>}
                <p className="muted">Affected: <span className="mono">{it.assets.slice(0, 10).join(', ')}{it.assets.length > 10 ? ` and ${it.assets.length - 10} more` : ''}</span></p>
                {tasks[it.code] ? <p><strong>Tracked:</strong> {tasks[it.code].assignee || 'unassigned'}, due {tasks[it.code].due}, <Link to="/fixes">{tasks[it.code].status.replace('_', ' ')}</Link></p>
                  : trackForm?.code === it.code ? (
                    <form className="form" onSubmit={track} style={{ maxWidth: 'none' }}>
                      <div className="form-row">
                        <label>Owner<select value={trackForm.who} onChange={(e) => setTrackForm({ ...trackForm, who: e.target.value })}>
                          <option value="">Unassigned</option>{people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
                        <label>Or the vendor's contact email<input type="email" value={trackForm.email || ''} onChange={(e) => setTrackForm({ ...trackForm, email: e.target.value })} /></label>
                      </div>
                      <label>Note<input value={trackForm.note || ''} onChange={(e) => setTrackForm({ ...trackForm, note: e.target.value })} /></label>
                      <p className="muted small">The due date is set from your deadline for {it.severity} issues; change it later on the Fixes page.</p>
                      <div className="actions"><button type="button" className="btn ghost" onClick={() => setTrackForm(null)}>Cancel</button><button className="btn primary">Create task</button></div>
                    </form>
                  ) : acceptForm?.code === it.code ? (
                    <form className="form" onSubmit={accept} style={{ maxWidth: 'none' }}>
                      <label>Why is this risk acceptable for now?<textarea rows={2} required minLength={10} value={acceptForm.reason} onChange={(e) => setAcceptForm({ ...acceptForm, reason: e.target.value })} /></label>
                      <label>Compensating controls (optional)<input value={acceptForm.controls} onChange={(e) => setAcceptForm({ ...acceptForm, controls: e.target.value })} /></label>
                      <label>Accept until<input type="date" required value={acceptForm.expires_on} onChange={(e) => setAcceptForm({ ...acceptForm, expires_on: e.target.value })} /></label>
                      <div className="actions"><button type="button" className="btn ghost" onClick={() => setAcceptForm(null)}>Cancel</button><button className="btn primary">Request acceptance</button></div>
                    </form>
                  ) : <p><button className="btn ghost" onClick={() => setTrackForm({ code: it.code, who: '' })}>Track fix</button>{' '}
                      <button className="btn ghost" onClick={() => setAcceptForm({ code: it.code, reason: '', controls: '', expires_on: new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10) })}>Accept risk</button></p>}
                {jira && (tickets[it.code]?.key
                  ? <p>Jira issue created: <a href={tickets[it.code].url} target="_blank" rel="noreferrer">{tickets[it.code].key}</a></p>
                  : <p><button className="btn ghost" disabled={tickets[it.code]?.busy} onClick={() => ticket(it.code)}>Create Jira issue</button>
                    {tickets[it.code]?.error && <span className="error"> {tickets[it.code].error}</span>}</p>)}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
