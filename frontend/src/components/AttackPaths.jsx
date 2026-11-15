import { useEffect, useState } from 'react'
import { api } from '../api.js'

const STATUS = { open: ['Open path', 'critical'], partly_open: ['Partly open', 'high'], entry_point: ['Entry point seen', 'medium'] }
const STATE = { evidence: '●', not_seen: '○', assumed: '◌' }

export default function AttackPaths({ entityId, version }) {
  const [paths, setPaths] = useState(null)
  const [open, setOpen] = useState(null)
  useEffect(() => { api.attackPaths(entityId).then(setPaths).catch(() => setPaths([])) }, [entityId, version])
  if (!paths) return null
  return (
    <section className="card">
      <div className="section-head">
        <div>
          <h2>Attacker's view</h2>
          <p className="muted small">How a red team would most likely try to break in, built from this company's findings and mapped to MITRE ATT&CK. ● evidence seen, ○ not seen from outside, ◌ assumed once the attacker is in. Nothing is attacked to produce this.</p>
        </div>
      </div>
      {paths.length === 0 ? <p className="muted">None of the common attack paths has a visible entry point. That is good, but it is not proof: an authorised red team assessment tests what cannot be seen from outside.</p> : paths.map((p) => {
        const [label, sev] = STATUS[p.status]
        return (
          <div key={p.id} className="dns-box">
            <div className="section-head" style={{ marginBottom: 4 }}>
              <button className="link-btn strong" onClick={() => setOpen(open === p.id ? null : p.id)} aria-expanded={open === p.id}>{p.name}</button>
              <span className={`sev sev-${sev}`}>{label}</span>
            </div>
            <div className="small muted">{p.impact} Evidence for {p.evidence_steps} of {p.checkable_steps} checkable steps.</div>
            {open === p.id && (
              <ol className="small" style={{ marginTop: 8 }}>
                {p.steps.map((s, i) => (
                  <li key={i} style={{ marginBottom: 6 }}>
                    <span title={s.state}>{STATE[s.state]}</span> <b>{s.stage}:</b> {s.step} <a className="chip" href={s.technique.url} target="_blank" rel="noreferrer">{s.technique.id} {s.technique.name}</a>
                    {s.evidence.length > 0 && <div className="muted">{s.evidence.map((e) => `${e.title} (${e.asset})`).join('; ')}</div>}
                  </li>
                ))}
              </ol>
            )}
          </div>
        )
      })}
    </section>
  )
}
