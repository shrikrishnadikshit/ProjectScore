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
  const [dark, setDark] = useState(null)
  const [cert, setCert] = useState(null)
  const [certMine, setCertMine] = useState(false)
  const [cisa, setCisa] = useState(null)
  const [cisaMine, setCisaMine] = useState(false)
  const [sources, setSources] = useState([])
  const [onlyMine, setOnlyMine] = useState(true)
  const [onlyAi, setOnlyAi] = useState(false)
  useEffect(() => { api.cisaAdvisories(days).then(setCisa).catch(() => setCisa(null)) }, [days])
  useEffect(() => { api.advisorySources().then((d) => setSources(d.sources)).catch(() => {}) }, [])
  useEffect(() => { api.certin(days).then(setCert).catch(() => setCert(null)) }, [days])
  useEffect(() => { api.threatEvents(days).then(setEvents).catch(() => setEvents({ events: [], catalogue_loaded: false })) }, [days])
  useEffect(() => { api.portfolioRansomware().then(setRsi).catch(() => {}); api.portfolioCertificates().then(setCerts).catch(() => {}); api.portfolioDarkWeb().then(setDark).catch(() => {}) }, [])
  const shown = events ? events.events.filter((e) => !onlyMine || e.affected.length).filter((e) => !onlyAi || e.ai) : []

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Threats</h1>
          <p className="muted">Newly announced vulnerabilities that attackers are already using, and which of your vendors they affect. Also: vendors seen on the dark web, which vendors are most exposed to ransomware, and whose certificates are lapsing.</p>
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

      {cert && cert.enabled && (
        <section className="card table-card">
          <div className="section-head" style={{ padding: '20px 20px 0' }}>
            <div>
              <h2>CERT-In advisories and vulnerability notes</h2>
              <p className="muted small">From the Indian Computer Emergency Response Team, matched against what our scans saw at your vendors. Source: CERT-In; open each item for the full text. More: <a href={cert.guidelines_url} target="_blank" rel="noreferrer">CERT-In guidelines</a>.</p>
            </div>
            <label className="check small"><input type="checkbox" checked={certMine} onChange={(e) => setCertMine(e.target.checked)} />Only ones affecting my vendors</label>
          </div>
          {cert.items.length === 0 ? <p className="muted pad">{cert.last_refresh ? 'Nothing published in this period.' : 'Loading from CERT-In; check back in a few minutes.'}</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Issued</th><th>Advisory or note</th><th>Severity</th><th>Affected vendors</th></tr></thead>
                <tbody>
                  {cert.items.filter((i) => !certMine || i.affected.length).map((i) => (
                    <tr key={i.code} className="static">
                      <td className="small">{i.issued}</td>
                      <td><a href={i.url} target="_blank" rel="noreferrer" className="strong">{i.title}</a><div className="small mono">{i.code}{i.cves.length > 0 && ` · ${i.cves.slice(0, 4).join(', ')}${i.cves.length > 4 ? ` +${i.cves.length - 4}` : ''}`}</div></td>
                      <td>{i.severity ? <span className={`sev sev-${i.severity === 'critical' ? 'critical' : i.severity === 'high' ? 'high' : i.severity === 'medium' ? 'medium' : 'low'}`}>{i.severity}</span> : <span className="muted small">{i.kind === 'advisory' ? 'advisory' : '—'}</span>}</td>
                      <td className="small">{i.affected.length === 0 ? <span className="muted">None</span> : i.affected.map((a) => <div key={a.id}><Link to={`/entities/${a.id}`}>{a.name}</Link> <span className="muted">({a.match})</span></div>)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {cisa && (
        <section className="card table-card">
          <div className="section-head" style={{ padding: '20px 20px 0' }}>
            <div>
              <h2>CISA advisories</h2>
              <p className="muted small">Cybersecurity and industrial control system (ICS) advisories from the US Cybersecurity and Infrastructure Security Agency, matched by CVE against what our scans saw at your vendors.</p>
            </div>
            <label className="check small"><input type="checkbox" checked={cisaMine} onChange={(e) => setCisaMine(e.target.checked)} />Only ones affecting my vendors</label>
          </div>
          {cisa.items.length === 0 ? <p className="muted pad">{cisa.error ? 'CISA could not be reached; we will try again shortly.' : 'Nothing published in this period yet, or still loading from CISA.'}</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Published</th><th>Advisory</th><th>Type</th><th>Affected vendors</th></tr></thead>
                <tbody>
                  {cisa.items.filter((i) => !cisaMine || i.affected.length).map((i) => (
                    <tr key={i.url} className="static">
                      <td className="small">{i.published}</td>
                      <td><a href={i.url} target="_blank" rel="noreferrer" className="strong">{i.title}</a><div className="small mono">{i.code}{i.cves.length > 0 && ` · ${i.cves.slice(0, 4).join(', ')}${i.cve_count > 4 ? ` +${i.cve_count - 4}` : ''}`}</div></td>
                      <td className="small">{i.kind === 'ics' ? 'ICS' : 'Cybersecurity'}</td>
                      <td className="small">{i.affected.length === 0 ? <span className="muted">None</span> : i.affected.map((a) => <div key={a.entity_id}><Link to={`/entities/${a.entity_id}`}>{a.name}</Link></div>)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {sources.length > 0 && (
        <section className="card">
          <h2>Where this data comes from</h2>
          <ul className="small">{sources.map((s) => <li key={s.url}><a href={s.url} target="_blank" rel="noreferrer">{s.name}</a>: <span className="muted">{s.use}</span></li>)}</ul>
          <p className="muted small">CVE records © The MITRE Corporation (CVE Program, CC BY 4.0). GitHub Advisory Database data is licensed under CC BY 4.0. NVD data is provided by NIST; this product uses NVD data but is not endorsed or certified by the NVD.</p>
        </section>
      )}

      {dark && (
        <section className="card table-card">
          <div style={{ padding: '20px 20px 0' }}>
            <h2>Dark web</h2>
            <p className="muted small">Vendors named on ransomware leak sites, and vendors whose staff logins were stolen by infostealer malware and traded on the dark web.{dark.attribution.length > 0 && ` Sources: ${dark.attribution.join(', ')}.`}{!dark.sources.leak_sites && ' The ransomware leak-site check is switched off until its data licence is in place.'}</p>
          </div>
          {dark.companies.length === 0 ? <p className="muted pad">None of your vendors has been seen on the dark web so far.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Company</th><th>Leak sites</th><th className="num">Infected staff computers</th><th>Last infection</th></tr></thead>
                <tbody>
                  {dark.companies.map((c) => (
                    <tr key={c.entity_id} className="static">
                      <td><Link to={`/entities/${c.entity_id}`} className="row-title">{c.name}</Link> <span className={`sev sev-${c.level}`}>{c.level}</span></td>
                      <td className="small">{c.leak_sites.length === 0 ? <span className="muted">Not listed</span> : c.leak_sites.map((l) => <div key={l.id}>{l.group} ({l.event_date})</div>)}</td>
                      <td className="num strong">{c.employees.toLocaleString()}</td>
                      <td className="small">{c.last_employee ? new Date(c.last_employee).toLocaleDateString() : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

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
