import { useEffect, useState } from 'react'
import { api } from '../api.js'

const LEVEL = { low: ['Low', 'low'], medium: ['Medium', 'medium'], high: ['High', 'high'] }
const STATUS = { open: 'Open path', partly_open: 'Partly open', entry_point: 'Entry point seen' }

export default function AiSecurity({ entityId, version }) {
  const [d, setD] = useState(null)
  useEffect(() => { api.aiSecurity(entityId).then(setD).catch(() => setD(null)) }, [entityId, version])
  if (!d) return null
  const [label, sev] = LEVEL[d.level]
  return (
    <section className="card">
      <div className="section-head">
        <div>
          <h2>AI security</h2>
          <p className="muted small">AI systems this company leaves open to the internet, the AI providers it uses, newly exploited flaws in AI software, and AI-driven attacks that apply to it.</p>
        </div>
        <span className={`sev sev-${sev}`}>AI exposure: {label}</span>
      </div>

      <h3>Exposed AI services</h3>
      {d.exposed_services.length === 0 ? <p className="muted small">No AI model servers, notebooks or vector databases seen open to the internet.</p> : (
        <ul className="small">
          {d.exposed_services.map((f) => <li key={f.id}><span className={`sev sev-${f.severity}`}>{f.severity}</span> {f.service || f.title} on <span className="mono">{f.asset}:{f.port}</span></li>)}
          <li className="muted">Matched on well-known ports, so please confirm with the company what is running there.</li>
        </ul>
      )}

      <h3>AI providers used</h3>
      {d.ai_vendors.length === 0 ? <p className="muted small">No AI providers visible in public DNS. Many are used without leaving a trace there, so ask in the questionnaire.</p>
        : <p className="small">{d.ai_vendors.map((v) => v.name).join(', ')}. Company data may be sent to these providers: check their terms and the company's AI policy.</p>}

      <h3>Newly exploited flaws in AI software (last {d.threat_days} days)</h3>
      {d.threat_events.length === 0 ? <p className="muted small">None in the catalogue of actively exploited vulnerabilities.</p> : (
        <ul className="small">
          {d.threat_events.map((e) => <li key={e.cve}><span className="mono">{e.cve}</span> {e.name} ({e.date_added}){e.affected && <span className="sev sev-critical" style={{ marginLeft: 6 }}>seen at this company</span>}</li>)}
        </ul>
      )}

      <h3>AI-driven attack paths</h3>
      {d.attack_paths.length === 0 ? <p className="muted small">No entry point seen for AI-powered impersonation or attacks on exposed AI services.</p> : (
        <ul className="small">{d.attack_paths.map((p) => <li key={p.id}><b>{p.name}</b> <span className="muted">({STATUS[p.status]})</span>: {p.impact}</li>)}</ul>
      )}

      <h3>AI rules and guidance</h3>
      <ul className="small">
        {d.frameworks.map((f) => <li key={f.id}><a href={f.url} target="_blank" rel="noreferrer">{f.name}</a> <span className="muted">({f.region})</span>: {f.note}</li>)}
      </ul>
      <p className="muted small">The vendor questionnaire includes an AI security section, and ISO/IEC 42001 certificates can be recorded under Certificates.</p>
    </section>
  )
}
