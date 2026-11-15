import { useEffect, useState } from 'react'
import { api } from '../api.js'

const LEVEL = { low: 'Nothing serious found', medium: 'Some exposure', high: 'Serious exposure', critical: 'Listed by a ransomware group' }

export default function DarkWeb({ entityId, version }) {
  const [d, setD] = useState(null)
  useEffect(() => { api.darkWeb(entityId).then(setD).catch(() => setD(null)) }, [entityId, version])
  if (!d) return null
  const s = d.infostealers
  return (
    <section className="card">
      <div className="section-head">
        <div>
          <h2>Dark web</h2>
          <p className="muted small">What criminals are publishing or selling about this company: ransomware leak-site listings and logins stolen by infostealer malware. We use public trackers of these sites; we never visit or buy from them.</p>
        </div>
        <span className={`sev sev-${d.level === 'low' ? 'low' : d.level}`}>{LEVEL[d.level]}</span>
      </div>

      <h3>Ransomware leak sites</h3>
      {!d.sources.leak_sites ? <p className="muted small">This check is switched off until its data licence is in place.</p>
        : d.leak_sites.length === 0 ? <p className="muted small">Not named on any tracked ransomware leak site in the last 12 months.</p> : (
          <ul className="small">
            {d.leak_sites.map((l) => (
              <li key={l.id}><span className={`sev sev-${l.severity}`}>{l.severity}</span> Named by <b>{l.group}</b> on {l.event_date}
                {l.matched_on === 'name' && <span className="muted"> (matched on company name: please confirm)</span>}
                {l.link && <> · <a href={l.link} target="_blank" rel="noreferrer">details</a></>}</li>
            ))}
          </ul>
        )}

      <h3>Logins stolen by infostealer malware</h3>
      {!d.sources.infostealers ? <p className="muted small">This check is switched off.</p>
        : s.employees === 0 && s.users === 0 ? <p className="muted small">No infected computers linked to this company's domain.</p> : (
          <ul className="small">
            {s.employees > 0 && <li><b>{s.employees.toLocaleString()}</b> employee computer{s.employees === 1 ? '' : 's'} infected{s.last_employee && `, most recently on ${new Date(s.last_employee).toLocaleDateString()}`}{s.families.length > 0 && ` (malware: ${s.families.join(', ')})`}. Stolen staff logins are a common way into a company for ransomware gangs.</li>}
            {s.employee_logins.length > 0 && <li className="muted">Stolen logins were for: {s.employee_logins.map((u) => u.url).join(', ')}</li>}
            {s.users > 0 && <li><b>{s.users.toLocaleString()}</b> customers or users had their logins to this company's sites stolen from their own computers.</li>}
          </ul>
        )}
      {d.attribution.length > 0 && <p className="muted small">Sources: {d.attribution.join(', ')}. Counts only: no names, emails or passwords are collected or shown.</p>}
    </section>
  )
}
