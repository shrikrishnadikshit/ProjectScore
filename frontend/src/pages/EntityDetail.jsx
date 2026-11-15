import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { Link, useOutletContext, useParams, useSearchParams } from 'react-router-dom'
import { api, FACTOR_LABELS, SEVERITY_ORDER } from '../api.js'
import { GradeBadge, ScoreGauge, gradeClass } from '../components/Grade.jsx'
import History from '../components/History.jsx'
import Frameworks from '../components/Frameworks.jsx'
import Insights from '../components/Insights.jsx'
import Questionnaires from '../components/Questionnaires.jsx'
import RiskEstimate from '../components/RiskEstimate.jsx'
import Incidents from '../components/Incidents.jsx'
import FixPlan from '../components/FixPlan.jsx'
import Vendors from '../components/Vendors.jsx'
import Ransomware from '../components/Ransomware.jsx'
import Certificates from '../components/Certificates.jsx'
import Systems from '../components/Systems.jsx'
import AttackPaths from '../components/AttackPaths.jsx'
import AiSecurity from '../components/AiSecurity.jsx'
import VendorShares from '../components/VendorShares.jsx'

const POLL_MS = 3000
const POLL_LIMIT = 100 // up to 5 minutes; discovery can take a while for large estates

export default function EntityDetail() {
  const { id } = useParams()
  const { user } = useOutletContext()
  const [params, setParams] = useSearchParams()
  const [entity, setEntity] = useState(null)
  const [scores, setScores] = useState([])
  const [error, setError] = useState(null)
  const [scanning, setScanning] = useState(params.get('scanning') === '1')
  const [showTrace, setShowTrace] = useState(false)
  const [notice, setNotice] = useState(null)
  const [disputes, setDisputes] = useState({})
  const [disputing, setDisputing] = useState(null)
  const polls = useRef(0)

  const load = useCallback(async () => {
    const [e, s, d] = await Promise.all([api.getEntity(id), api.getScores(id), api.entityDisputes(id).catch(() => [])])
    setEntity(e)
    setScores(s)
    // Latest dispute per finding (the API returns newest first).
    const byFinding = {}
    for (const row of d) if (!byFinding[row.finding_id]) byFinding[row.finding_id] = row
    setDisputes(byFinding)
    return s.length
  }, [id])

  useEffect(() => {
    load().catch((e) => setError(e.message))
  }, [load])

  // While a scan runs, poll until a new score appears.
  useEffect(() => {
    if (!scanning) return
    const startCount = scores.length
    polls.current = 0
    const timer = setInterval(async () => {
      polls.current += 1
      try {
        const count = await load()
        if (count > startCount || polls.current >= POLL_LIMIT) {
          setScanning(false)
          setParams({}, { replace: true })
        }
      } catch {
        setScanning(false)
      }
    }, POLL_MS)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanning])

  async function rescan() {
    setNotice(null)
    try {
      await api.startScan(id)
      setScanning(true)
    } catch (e) {
      setNotice(e.message.charAt(0).toUpperCase() + e.message.slice(1) + '.')
    }
  }

  if (error) return <div className="card error">{error}</div>
  if (!entity) return <div className="muted">Loading…</div>

  const latest = scores[scores.length - 1]
  const factors = Object.entries(entity.factors).sort((a, b) => b[1].weight - a[1].weight)
  const findings = [...entity.findings].sort(
    (a, b) => (a.priority ?? 4) - (b.priority ?? 4) || SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]).filter(([, n]) => n)

  return (
    <>
      <Link to="/" className="back">← Portfolio</Link>
      <div className="page-head">
        <div>
          <h1>{entity.name}</h1>
          <p className="muted">{entity.primary_domain}{entity.industry ? ` · ${entity.industry}` : ''} · Tier {entity.tier}
            {entity.assets?.length ? ` · ${entity.assets.length} internet-facing asset${entity.assets.length === 1 ? '' : 's'}` : ''}</p>
        </div>
        <div className="row-actions">
          {entity.score != null && <a className="btn ghost" href={`/api/entities/${id}/report.pdf`}>Download PDF report</a>}
          <button className="btn primary" onClick={rescan} disabled={scanning || entity.opted_out}>{scanning ? 'Scanning…' : 'Run new scan'}</button>
        </div>
      </div>

      {entity.opted_out && <div className="banner">This company's domain owner has opted out of scanning. Existing results are shown, but it will not be rescanned.</div>}
      {notice && <div className="banner">{notice}</div>}
      {scanning && <div className="banner">Scan in progress. This usually takes one to three minutes; the page updates by itself.</div>}

      <section className="overview">
        <div className="card score-card">
          <ScoreGauge score={entity.score} grade={entity.grade} />
          <div className="score-meta">
            <GradeBadge grade={entity.grade} size="lg" />
            <div>
              <div className="strong">{gradeText(entity.grade)}</div>
              <div className="muted small">
                {latest ? `Model ${latest.model_version} · ${new Date(latest.created_at).toLocaleString()}` : 'Not scanned yet'}
              </div>
              {latest?.trace?.coverage != null && latest.trace.coverage < 1 && (
                <div className="muted small">Based on {Math.round(latest.trace.coverage * 100)}% of rating factors (others not yet assessed).</div>
              )}
              {latest?.trace?.gates?.map((g) => (
                <div key={g.gate} className="error small">Score capped at {g.cap} due to a severe issue.</div>
              ))}
            </div>
          </div>
        </div>
        <div className="card">
          <h2>Score trend</h2>
          <History scores={scores} />
        </div>
      </section>

      {latest && <Insights entity={entity} user={user} version={latest.created_at} />}

      {latest && <RiskEstimate entityId={id} version={latest.created_at} />}

      <section className="card">
        <h2>Risk factors</h2>
        {factors.length === 0 ? <p className="muted">Run a scan to see factor grades.</p> : (
          <div className="factors">
            {factors.map(([key, f]) => (
              <div key={key} className="factor">
                <div className="factor-head">
                  <span>{FACTOR_LABELS[key] ?? key}</span>
                  <GradeBadge grade={f.grade} size="sm" />
                </div>
                <div className="bar"><div className={`bar-fill ${gradeClass(f.grade)}`} style={{ width: `${f.score}%` }} /></div>
                <div className="muted small">{Math.round(f.score)}/100 · weight {Math.round(f.weight * 100)}% · {f.assets} asset{f.assets === 1 ? '' : 's'}</div>
              </div>
            ))}
          </div>
        )}
      </section>

      {latest && <AttackPaths entityId={id} version={`${latest.created_at}-${findings.length}`} />}
      {latest && <AiSecurity entityId={id} version={`${latest.created_at}-${findings.length}`} />}

      {latest && <Ransomware entityId={id} version={`${latest.created_at}-${findings.length}`} />}

      {latest && <Systems entityId={id} version={`${latest.created_at}-${findings.length}`} />}

      {latest && <FixPlan entityId={id} version={`${latest.created_at}-${findings.length}`} />}

      <section className="card table-card">
        <div className="section-head">
          <h2>Open findings</h2>
          <div className="chips">{counts.map(([s, n]) => <span key={s} className={`sev sev-${s}`}>{n} {s}</span>)}</div>
        </div>
        {findings.length === 0 ? <p className="muted pad">No open findings.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Severity</th><th title="Severity combined with how important the affected system is. P1 = fix first.">Priority</th><th>Finding</th><th>Factor</th><th>Asset</th><th>First seen</th><th></th></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <Fragment key={f.id}>
                    <tr className="static">
                      <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                      <td><span className={`prio prio-${f.priority}`} title={f.asset_value ? `${f.asset_value}-value system` : 'system importance not yet known'}>P{f.priority}</span></td>
                      <td>{f.title}<CveList ids={f.evidence?.cves} info={entity.cves} />{f.attack?.length > 0 && <div className="chips" style={{ marginTop: 4 }}>{f.attack.map((t) => <a key={t.id} className="chip small" href={t.url} target="_blank" rel="noreferrer" title={`MITRE ATT&CK ${t.id}`}>{t.id} {t.name}</a>)}</div>}</td>
                      <td className="muted small">{FACTOR_LABELS[f.risk_factor] ?? f.risk_factor}</td>
                      <td className="mono small">{f.asset}</td>
                      <td className="muted small">{new Date(f.first_seen).toLocaleDateString()}</td>
                      <td>
                        {disputes[f.id]?.status === 'pending' ? <span className="role">Dispute under review</span>
                          : disputes[f.id]?.status === 'rejected' ? <span className="role" title={disputes[f.id].reviewer_note || ''}>Dispute rejected</span>
                          : <button className="btn ghost tiny" onClick={() => setDisputing(disputing === f.id ? null : f.id)}>Dispute</button>}
                      </td>
                    </tr>
                    {disputing === f.id && (
                      <tr className="static"><td colSpan={6}>
                        <DisputeForm onCancel={() => setDisputing(null)} onSubmit={async (reason) => {
                          await api.disputeFinding(f.id, reason)
                          setDisputing(null)
                          setNotice('Thank you. Your dispute has been sent for review. If it is accepted, the finding is removed and the score is recalculated.')
                          await load()
                        }} />
                      </td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <VendorShares entityId={id} entityName={entity.name} user={user} />

      <Questionnaires entityId={id} user={user} />

      <Certificates entityId={id} />

      <Vendors entityId={id} entityName={entity.name} version={latest?.created_at} />

      {user.role === 'owner' && <Incidents entityId={id} />}

      {latest && <Frameworks entityId={id} version={`${latest.created_at}-${findings.length}`} />}

      {entity.assets?.length > 0 && (
        <section className="card">
          <h2>Discovered assets</h2>
          <p className="muted small">Found passively from certificate logs, DNS and internet registry records. Up to 100 hostnames and 256 IP addresses are checked per company.</p>
          {[['domain', 'Domains'], ['subdomain', 'Subdomains'], ['netblock', 'Registered IP ranges'], ['ip', 'IP addresses']].map(([type, label]) => {
            const items = entity.assets.filter((a) => a.type === type)
            return items.length ? (
              <div key={type} className="asset-group">
                <div className="small strong">{label} ({items.length})</div>
                <div className="asset-list">{items.map((a) => <span key={a.value} className="mono small asset">{a.value}</span>)}</div>
              </div>
            ) : null
          })}
        </section>
      )}

      {latest && (
        <section className="card">
          <div className="section-head">
            <h2>How this score was calculated</h2>
            <button className="btn ghost" onClick={() => setShowTrace(!showTrace)}>{showTrace ? 'Hide' : 'Show'} details</button>
          </div>
          {showTrace && (
            <div className="table-scroll">
              <p className="muted small">Each finding contributes severity × confidence × time decay to its factor's penalty, which is then normalised by the number of assets.</p>
              <table>
                <thead><tr><th>Factor</th><th>Finding</th><th>Asset</th><th className="num">Severity</th><th className="num">Confidence</th><th className="num">Decay</th><th className="num">Points</th></tr></thead>
                <tbody>
                  {latest.trace.contributions.map((c, i) => (
                    <tr key={i} className="static">
                      <td className="small">{FACTOR_LABELS[c.factor] ?? c.factor}</td>
                      <td className="mono small">{c.code}</td>
                      <td className="mono small">{c.asset}</td>
                      <td className="num">{c.S}</td><td className="num">{c.C}</td><td className="num">{c.D}</td>
                      <td className="num strong">{c.contribution}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </>
  )
}

function gradeText(grade) {
  return {
    A: 'Advanced: strong external hygiene',
    B: 'Good: minor weaknesses',
    C: 'Intermediate: material weaknesses',
    D: 'Basic: significant weaknesses',
    F: 'Critical: severe exposures',
  }[grade] ?? 'Awaiting first scan'
}

function DisputeForm({ onSubmit, onCancel }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try { await onSubmit(reason) } catch (err) {
      setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.')
      setBusy(false)
    }
  }
  return (
    <form className="form" onSubmit={submit} style={{ maxWidth: 'none' }}>
      <label>Why is this finding wrong?
        <textarea rows={3} required minLength={10} value={reason} onChange={(e) => setReason(e.target.value)}
          placeholder="For example: this host belongs to our CDN provider, not to us; or the record was fixed on 10 November." />
      </label>
      {error && <p className="error">{error}</p>}
      <div className="actions">
        <button type="button" className="btn ghost" onClick={onCancel}>Cancel</button>
        <button className="btn primary" disabled={busy}>{busy ? 'Sending…' : 'Send dispute'}</button>
      </div>
    </form>
  )
}

function cvssClass(score) {
  return score == null ? 'none' : score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low'
}

function CveList({ ids, info }) {
  if (!ids?.length) return null
  const sorted = [...ids].sort((a, b) => (info?.[b]?.cvss ?? -1) - (info?.[a]?.cvss ?? -1))
  return (
    <div className="cve-list">
      {sorted.slice(0, 8).map((id) => {
        const c = info?.[id]
        return (
          <span key={id} className="cve" title={c?.description || ''}>
            <a href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer">{id}</a>
            {c ? <>
              <span className={`cvss cvss-${cvssClass(c.cvss)}`} title={c.vector || ''}>CVSS {c.cvss ?? 'n/a'}</span>
              {c.epss != null && <span className="muted" title="EPSS: chance of exploitation in the next 30 days">EPSS {(c.epss * 100).toFixed(c.epss < 0.01 ? 2 : 0)}%</span>}
            </> : <span className="muted">score pending</span>}
          </span>
        )
      })}
      {ids.length > 8 && <span className="muted small">and {ids.length - 8} more</span>}
    </div>
  )
}
