import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

const LEVEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Very high' }
const STATUS = { valid: 'Valid', expiring: 'Expiring soon', expired: 'Expired', no_expiry: 'No expiry date' }

export default function Threats() {
  const [days, setDays] = useState(30)
  const [events, setEvents] = useState(null)
  const [rsi, setRsi] = useState([])
  const [certs, setCerts] = useState(null)
  const [onlyMine, setOnlyMine] = useState(true)
  const [onlyAi, setOnlyAi] = useState(false)
  useEffect(() => { api.threatEvents(days).then(setEvents).catch(() => setEvents({ events: [], catalogue_loaded: false })) }, [days])
  useEffect(() => { api.portfolioRansomware().then(setRsi).catch(() => {}); api.portfolioCertificates().then(setCerts).catch(() => {}) }, [])
  const shown = events ? events.events.filter((e) => !onlyMine || e.affected.length).filter((e) => !onlyAi || e.ai) : []

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Threats</h1>
          <p className="muted">Newly announced vulnerabilities that attackers are already using, and which of your vendors they affect. Also: which vendors are most exposed to ransomware, and whose certificates are lapsing.</p>
        </div>
      </div>

      <section className="card table-card">
        <div className="section-head">
          <div>
            <h2>Threat events</h2>
            <p className="muted small">From the CISA Known Exploited Vulnerabilities catalogue, matched against what our scans saw at each vendor. “Confirmed” means we saw the exact vulnerability; “same software” means the vendor runs the affected product and should check its version.</p>
          </div>
          <div className="row-actions">
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option>
            </select>
            <label className="check small"><input type="checkbox" checked={onlyMine} onChange={(e) => setOnlyMine(e.target.checked)} />Only ones affecting my vendors</label>
            <label className="check small"><input type="checkbox" checked={onlyAi} onChange={(e) => setOnlyAi(e.target.checked)} />Only AI software</label>
          </div>
        </div>
        {!events ? <p className="muted pad">Loading…</p> : !events.catalogue_loaded ? <p className="muted pad">The vulnerability catalogue could not be loaded just now. Try again in a few minutes.</p> : shown.length === 0 ? (
          <p className="muted pad">{onlyAi ? 'No newly exploited vulnerabilities in AI software match these filters.' : onlyMine ? `None of the ${events.events.length} newly exploited vulnerabilities in this period match your vendors.` : 'No new entries in this period.'}</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Added</th><th>Vulnerability</th><th>Affected vendors</th></tr></thead>
              <tbody>
                {shown.map((e) => (
                  <tr key={e.cveID} className="static">
                    <td className="small">{e.dateAdded}</td>
                    <td>
                      <div className="strong">{e.vulnerabilityName}</div>
                      <div className="small"><span className="mono">{e.cveID}</span> · {e.vendorProject} {e.product}{e.ai && <span className="sev sev-info" style={{ marginLeft: 6 }}>AI</span>}{e.ransomware && <span className="sev sev-critical" style={{ marginLeft: 6 }}>used in ransomware</span>}</div>
                      {e.requiredAction && <div className="small muted">{e.requiredAction}</div>}
                    </td>
                    <td className="small">{e.affected.length === 0 ? <span className="muted">None</span> : e.affected.map((a) => <div key={a.id}><Link to={`/entities/${a.id}`}>{a.name}</Link> <span className="muted">({a.match})</span></div>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card table-card">
        <h2 style={{ padding: '20px 20px 0' }}>Ransomware susceptibility by vendor</h2>
        {rsi.length === 0 ? <p className="muted pad">No companies yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Company</th><th className="num">Index</th><th>Level</th><th>Main reason</th></tr></thead>
              <tbody>
                {rsi.map((r) => (
                  <tr key={r.entity_id} className="static">
                    <td><Link to={`/entities/${r.entity_id}`} className="row-title">{r.name}</Link></td>
                    <td className="num strong">{r.index.toFixed(2)}</td>
                    <td><span className={`sev sev-${r.level}`}>{LEVEL[r.level]}</span></td>
                    <td className="small muted">{r.top_signal || 'No warning signs seen'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {certs && (
        <section className="card table-card">
          <h2 style={{ padding: '20px 20px 0' }}>Certificates ({certs.expired} expired, {certs.expiring} expiring soon)</h2>
          {certs.certificates.length === 0 ? <p className="muted pad">No certificates recorded yet. Add them on each company's page.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Company</th><th>Certificate</th><th>Expires</th><th>Status</th></tr></thead>
                <tbody>
                  {certs.certificates.filter((c) => c.status !== 'valid').concat(certs.certificates.filter((c) => c.status === 'valid')).map((c) => (
                    <tr key={c.id} className="static">
                      <td><Link to={`/entities/${c.entity_id}`}>{c.entity}</Link></td>
                      <td className="small">{c.kind_label}</td>
                      <td className="small">{c.expires_on ? new Date(c.expires_on).toLocaleDateString() : '—'}</td>
                      <td><span className={`sev sev-${c.status === 'expired' ? 'high' : c.status === 'expiring' ? 'medium' : 'info'}`}>{STATUS[c.status]}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {certs.without_any.length > 0 && <p className="muted small pad">No certificate on record for: {certs.without_any.slice(0, 20).join(', ')}{certs.without_any.length > 20 ? ` and ${certs.without_any.length - 20} more` : ''}.</p>}
        </section>
      )}
    </>
  )
}
