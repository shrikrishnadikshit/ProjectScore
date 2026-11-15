import { useEffect, useState } from 'react'
import { api } from '../api.js'

const LEVEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Very high' }
const SEV = { low: 'low', medium: 'medium', high: 'high', critical: 'critical' }

export default function Ransomware({ entityId, version }) {
  const [r, setR] = useState(null)
  const [show, setShow] = useState(false)
  useEffect(() => { api.entityRansomware(entityId).then(setR).catch(() => setR(null)) }, [entityId, version])
  if (!r) return null
  return (
    <section className="card">
      <div className="section-head">
        <h2>Ransomware susceptibility</h2>
        <span className={`sev sev-${SEV[r.level]}`}>{LEVEL[r.level]}</span>
      </div>
      <div className="stats">
        <div><div className="stat">{r.index.toFixed(2)}</div><div className="muted small">on a scale from 0.00 (unlikely) to 1.00 (very likely)</div></div>
        <div style={{ flex: 2 }}>
          <div className="meter" aria-hidden="true" style={{ height: 8, borderRadius: 4, background: 'var(--border)', overflow: 'hidden', marginTop: 12 }}>
            <div style={{ width: `${Math.round(r.index * 100)}%`, height: '100%', background: r.index >= 0.5 ? 'var(--grade-f)' : r.index >= 0.3 ? 'var(--grade-c)' : 'var(--grade-a)' }} />
          </div>
          <div className="muted small" style={{ marginTop: 6 }}>{r.signals.length === 0 ? 'None of the usual ransomware entry points were seen from outside.' : `${r.signals.length} warning sign${r.signals.length > 1 ? 's' : ''} found`}</div>
        </div>
      </div>
      {r.signals.length > 0 && (
        <ul className="small">
          {r.signals.map((s) => <li key={s.id}>{s.label}{s.examples.length > 0 && <span className="mono muted"> · {s.examples.join(', ')}</span>}</li>)}
        </ul>
      )}
      <p className="muted small">Based on how ransomware gangs usually get in: exposed remote access, exploited software, phishing and stolen passwords. A guide for prioritising, not a prediction. <button className="link-btn" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'} weights</button></p>
      {show && <ul className="small muted">{r.signals.map((s) => <li key={s.id}>{s.label}: +{s.weight}</li>)}<li>{r.method}</li></ul>}
    </section>
  )
}
