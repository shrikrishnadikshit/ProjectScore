import { useEffect, useState } from 'react'
import { Link, Navigate, useOutletContext, useParams } from 'react-router-dom'
import { api, SEVERITY_ORDER } from '../api.js'

const cap = (m) => m.charAt(0).toUpperCase() + m.slice(1)

function ScanResults({ id }) {
  const [scan, setScan] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    let timer
    const load = () => api.getActiveScan(id).then((s) => {
      setScan(s)
      if (s.status === 'queued' || s.status === 'running') timer = setTimeout(load, 10000)
    }).catch((e) => setError(e.message))
    load()
    return () => clearTimeout(timer)
  }, [id])
  if (error) return <div className="card error">{error}</div>
  if (!scan) return <div className="muted">Loading…</div>
  const counts = SEVERITY_ORDER.map((s) => [s, scan.results.filter((r) => r.severity === s).length]).filter(([, n]) => n)
  return (
    <>
      <Link to="/in-depth" className="back">← In-depth scans</Link>
      <div className="page-head">
        <div>
          <h1>In-depth scan: {scan.domain}</h1>
          <p className="muted">Authorised by {scan.authoriser_name}, {scan.authoriser_title} · {new Date(scan.created_at).toLocaleString()}</p>
        </div>
      </div>
      {(scan.status === 'queued' || scan.status === 'running') && <div className="banner">Scan in progress across {scan.targets.length || 'the'} hosts. This can take 10 to 40 minutes; this page updates by itself.</div>}
      {scan.status === 'failed' && <div className="banner error">The scan failed: {scan.error}</div>}
      <section className="card">
        <h2>Scope</h2>
        <div className="asset-list">{scan.targets.map((t) => <span key={t} className="mono small asset">{t}</span>)}</div>
        <p className="muted small" style={{ marginTop: 12 }}>These results come from active testing you authorised. They are private to your organisation and do not change the public security rating.</p>
      </section>
      {scan.status === 'done' && (
        <section className="card table-card">
          <div className="section-head">
            <h2>Findings ({scan.results.length})</h2>
            <div className="chips">{counts.map(([s, n]) => <span key={s} className={`sev sev-${s}`}>{n} {s}</span>)}</div>
          </div>
          {scan.results.length === 0 ? <p className="muted pad">No issues found by the scanner's checks.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Severity</th><th>Issue</th><th>Where</th></tr></thead>
                <tbody>
                  {scan.results.map((r, i) => (
                    <tr key={i} className="static">
                      <td><span className={`sev sev-${r.severity}`}>{r.severity}</span></td>
                      <td>
                        <div className="strong">{r.name}</div>
                        {r.cves.length > 0 && <div className="mono small">{r.cves.join(', ')}</div>}
                        {r.description && <div className="muted small">{r.description}</div>}
                        {r.remediation && <div className="small"><b>Fix:</b> {r.remediation}</div>}
                      </td>
                      <td className="mono small">{r.matched_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
      <section className="card">
        <h2>Authorisation record</h2>
        <p className="statement">{scan.authorisation_text}</p>
      </section>
    </>
  )
}

export default function DeepScans() {
  const { user } = useOutletContext()
  const { scanId } = useParams()
  const [verifs, setVerifs] = useState([])
  const [scans, setScans] = useState([])
  const [config, setConfig] = useState(null)
  const [newDomain, setNewDomain] = useState('')
  const [auth, setAuth] = useState({ domain: '', authoriser_name: '', authoriser_title: '', confirm: false })
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)

  const load = () => Promise.all([api.listVerifications(), api.listActiveScans(), api.activeConfig()])
    .then(([v, s, c]) => { setVerifs(v); setScans(s); setConfig(c) })
    .catch((e) => setError(e.message))
  useEffect(() => { if (!scanId) load() }, [scanId])

  if (user.role !== 'admin' && user.role !== 'owner') return <Navigate to="/" replace />
  if (scanId) return <ScanResults id={scanId} />

  const run = async (fn, ok) => {
    setError(null); setNotice(null)
    try { await fn(); if (ok) setNotice(ok); await load() } catch (e) { setError(cap(e.message) + '.') }
  }
  const verified = verifs.filter((v) => v.valid)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>In-depth scans</h1>
          <p className="muted">Active vulnerability testing of your own websites with the free Nuclei scanner. Only for domains your organisation has proved it controls, and only with written authorisation. Results are private and do not affect ratings.</p>
        </div>
      </div>
      {config && !config.available && <div className="banner">The scanner is not installed on this server yet. Domain verification still works.</div>}
      {error && <div className="banner error">{error}</div>}
      {notice && <div className="banner">{notice}</div>}

      <div className="steps">
        <section className="card">
          <h2><span className="step-num">1</span>Prove you control the domain</h2>
          <form className="form" style={{ maxWidth: 'none' }} onSubmit={(e) => { e.preventDefault(); run(() => api.startVerification(newDomain), null); setNewDomain('') }}>
            <div className="form-row">
              <label>Domain<input required value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="yourcompany.com" /></label>
              <div style={{ alignSelf: 'end' }}><button className="btn primary">Get DNS record</button></div>
            </div>
          </form>
          {verifs.map((v) => (
            <div key={v.id} className="dns-box">
              <div className="section-head" style={{ marginBottom: 0 }}>
                <span className="strong">{v.domain}</span>
                {v.valid ? <span className="ok">Verified {new Date(v.verified_at).toLocaleDateString()}</span>
                  : <button className="btn ghost tiny" onClick={() => run(() => api.checkVerification(v.id), `${v.domain} verified.`)}>Check now</button>}
              </div>
              {!v.valid && (
                <>
                  <div className="small">Ask whoever manages your DNS to add this <b>TXT</b> record, then press Check now:</div>
                  <div className="small">Name: <span className="mono">{v.record_name}</span></div>
                  <div className="small">Value: <span className="mono">{v.record_value}</span></div>
                </>
              )}
            </div>
          ))}
        </section>

        <section className="card">
          <h2><span className="step-num">2</span>Authorise and start a scan</h2>
          {verified.length === 0 ? <p className="muted">Verify a domain first.</p> : (
            <form className="form" style={{ maxWidth: 'none' }} onSubmit={(e) => {
              e.preventDefault()
              run(() => api.startActiveScan(auth), 'Scan started. It appears below; open it to follow progress.')
              setAuth({ ...auth, confirm: false })
            }}>
              <div className="form-row">
                <label>Domain
                  <select required value={auth.domain} onChange={(e) => setAuth({ ...auth, domain: e.target.value })}>
                    <option value="">Choose…</option>
                    {verified.map((v) => <option key={v.id} value={v.domain}>{v.domain}</option>)}
                  </select>
                </label>
                <div />
              </div>
              <div className="form-row">
                <label>Authorised by (full name)<input required value={auth.authoriser_name} onChange={(e) => setAuth({ ...auth, authoriser_name: e.target.value })} /></label>
                <label>Job title<input required value={auth.authoriser_title} onChange={(e) => setAuth({ ...auth, authoriser_title: e.target.value })} placeholder="e.g. CISO, IT Director" /></label>
              </div>
              {config && auth.domain && <p className="statement">{config.authorisation_text.replaceAll('{domain}', auth.domain)}</p>}
              <label className="check"><input type="checkbox" checked={auth.confirm} onChange={(e) => setAuth({ ...auth, confirm: e.target.checked })} />I agree to the statement above. This record is stored with the scan.</label>
              <div className="actions"><button className="btn primary" disabled={!auth.confirm || !auth.domain}>Start in-depth scan</button></div>
            </form>
          )}
        </section>

        <section className="card table-card">
          <h2 style={{ padding: '20px 20px 0' }}><span className="step-num">3</span>Scans</h2>
          {scans.length === 0 ? <p className="muted pad">No scans yet.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Domain</th><th>Started</th><th>Status</th><th className="num">Findings</th></tr></thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id} onClick={() => { window.location.href = `/in-depth/${s.id}` }}>
                      <td><Link to={`/in-depth/${s.id}`} className="row-title">{s.domain}</Link></td>
                      <td className="small muted">{new Date(s.created_at).toLocaleString()}</td>
                      <td><span className="role">{s.status}</span></td>
                      <td className="num">{s.status === 'done' ? s.finding_count : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  )
}
