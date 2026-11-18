import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function ThreatGroups({ entityId, version }) {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(null)
  useEffect(() => { api.entityThreatGroups(entityId).then(setData).catch(() => setData(null)) }, [entityId, version])
  if (!data) return null
  return (
    <section className="card">
      <h2>Ransomware groups that could get in</h2>
      <p className="muted small">Known ransomware groups and families whose usual way in matches something we saw at this company, from MITRE ATT&CK's public records of how each one operates. It shows who could exploit these weaknesses, not that anyone is targeting this company.</p>
      {data.groups.length === 0 ? <p className="muted small">None of the known groups' usual entry techniques matches what we see from outside.</p> : (
        <div className="fw-list">
          {data.groups.map((g) => (
            <div key={g.id} className="fw-row">
              <button className="fw-head plan-btn" onClick={() => setOpen(open === g.id ? null : g.id)} aria-expanded={open === g.id}>
                <span className="small strong">{g.name}</span>
                <span className="small muted">{g.kind === 'group' ? 'Group' : 'Ransomware'}{g.aliases.length ? ` · also ${g.aliases.slice(0, 2).join(', ')}` : ''}</span>
                <span className="small plan-meta">{g.entry.map((h) => h.name).join(', ')}</span>
              </button>
              {open === g.id && (
                <div className="plan-body small">
                  {g.ransomware.length > 0 && g.kind === 'group' && <p>Ransomware used: {g.ransomware.join(', ')}</p>}
                  <p><strong>How it could get in here:</strong></p>
                  <ul>{g.entry.map((h) => <li key={h.id}><a href={h.url} target="_blank" rel="noreferrer">{h.id} {h.name}</a> <span className="muted">because of: {h.evidence.join('; ')}</span></li>)}</ul>
                  {g.other.length > 0 && <p className="muted">Other techniques it uses that we also see evidence for: {g.other.map((h) => h.name).join(', ')}.</p>}
                  <p><a href={g.url} target="_blank" rel="noreferrer">Full profile on MITRE ATT&CK</a></p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="muted small" style={{ marginTop: 8 }}>MITRE ATT&CK v{data.version}. {data.notice}</p>
    </section>
  )
}
