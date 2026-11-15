import { useEffect, useState } from 'react'
import { api } from '../api.js'

const STATUS = {
  issues: ['Issues found', 'status-issues'],
  no_issues: ['No issues seen', 'status-ok'],
  not_assessed: ['Not assessed yet', 'status-na'],
  out_of_scope: ['Not visible from outside', 'status-na'],
}

export default function Frameworks({ entityId, version }) {
  const [data, setData] = useState(null)
  const [active, setActive] = useState(null)
  const [open, setOpen] = useState(null)
  const [showAll, setShowAll] = useState(false)
  useEffect(() => { api.entityFrameworks(entityId).then(setData).catch(() => setData([])) }, [entityId, version])
  if (!data?.length) return null
  const visible = showAll ? data : data.filter((f) => f.preferred !== false)
  const fw = data.find((f) => f.key === active) ?? visible[0] ?? data[0]
  const regions = [...new Set(data.map((f) => f.region_name))]
  const flagged = fw.controls.filter((c) => c.status === 'issues').length

  return (
    <section className="card">
      <div className="section-head">
        <h2>Framework mapping</h2>
        <span className="muted small">{flagged} of {fw.controls.length} controls with issues</span>
      </div>
      <div className="row-actions" style={{ marginBottom: 12, flexWrap: 'wrap' }}>
        <select value={fw.key} onChange={(e) => { setActive(e.target.value); setOpen(null) }} aria-label="Framework">
          {(showAll ? regions : [...new Set(visible.map((f) => f.region_name))]).map((r) => (
            <optgroup key={r} label={r}>
              {visible.filter((f) => f.region_name === r).map((f) => <option key={f.key} value={f.key}>{f.name}</option>)}
            </optgroup>
          ))}
        </select>
        <label className="check small"><input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />Show frameworks for all countries ({data.length})</label>
      </div>
      <div className="fw-list">
        {fw.controls.map((c) => {
          const [label, cls] = STATUS[c.status]
          const expandable = c.findings.length > 0
          return (
            <div key={c.id} className="fw-row">
              <button className="fw-head" disabled={!expandable} onClick={() => setOpen(open === c.id ? null : c.id)} aria-expanded={open === c.id}>
                <span className="fw-id mono small">{c.id}</span>
                <span className="fw-title small">{c.title}</span>
                <span className={`fw-status small ${cls}`}>{label}{expandable ? ` (${c.findings.length})` : ''}</span>
              </button>
              {open === c.id && (
                <ul className="fw-findings">
                  {c.findings.map((f) => <li key={f.id} className="small"><span className={`sev sev-${f.severity}`}>{f.severity}</span> {f.title} <span className="mono muted">{f.asset}</span></li>)}
                </ul>
              )}
            </div>
          )
        })}
      </div>
      <p className="muted small" style={{ marginTop: 12 }}>Indicative only. Outside-in findings are evidence about these controls, not a compliance assessment: "no issues seen" means nothing was visible from the internet, not that the control is in place.</p>
    </section>
  )
}
