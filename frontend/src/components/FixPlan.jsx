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
                <p className="muted">Affected: <span className="mono">{it.assets.slice(0, 10).join(', ')}{it.assets.length > 10 ? ` and ${it.assets.length - 10} more` : ''}</span></p>
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
