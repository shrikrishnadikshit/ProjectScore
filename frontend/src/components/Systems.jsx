import { useEffect, useState } from 'react'
import { api } from '../api.js'

const VALUE = { high: 'High', medium: 'Medium', low: 'Low' }
const SEVS = ['critical', 'high', 'medium', 'low']
const PRIO = { critical: { high: 1, medium: 1, low: 2 }, high: { high: 1, medium: 2, low: 3 }, medium: { high: 2, medium: 3, low: 4 }, low: { high: 3, medium: 4, low: 4 } }
let regionNames
try { regionNames = new Intl.DisplayNames(['en'], { type: 'region' }) } catch { regionNames = null }
const country = (c) => (c && regionNames ? regionNames.of(c) : c) || 'Unknown'

export default function Systems({ entityId, version }) {
  const [d, setD] = useState(null)
  const [all, setAll] = useState(false)
  useEffect(() => { api.entityAssets(entityId).then(setD).catch(() => setD(null)) }, [entityId, version])
  if (!d || d.assets.length === 0) return null
  const rows = all ? d.assets : d.assets.slice(0, 12)
  const h = d.hosting
  return (
    <section className="card table-card">
      <div className="section-head">
        <div>
          <h2>Systems and hosting</h2>
          <p className="muted small">How important each system is, judged from what it does: logins, payments and email count most. Issues are ranked by severity and importance, P1 first.</p>
        </div>
      </div>
      <div className="stats pad" style={{ paddingTop: 0 }}>
        <div><div className="stat">{d.counts.high}</div><div className="muted small">high-value systems</div></div>
        <div><div className="stat">{d.priorities['1']}</div><div className="muted small">top-priority (P1) issues</div></div>
        <div><div className="stat">{h.located ? `${h.outside_home} of ${h.located}` : '—'}</div><div className="muted small">systems hosted outside {country(h.home_country)}</div></div>
      </div>
      {h.high_risk.length > 0 && <div className="banner error" style={{ margin: '0 20px 12px' }}>{h.high_risk.length} system(s) hosted in high-risk countries: {h.countries.filter((c) => c.high_risk).map((c) => c.name).join(', ')}.</div>}
      <div className="pad" style={{ display: 'flex', gap: 24, flexWrap: 'wrap', paddingTop: 0 }}>
        <div>
          <div className="small strong" style={{ marginBottom: 6 }}>Open issues by severity and system importance</div>
          <table className="matrix">
            <thead><tr><th></th><th>High value</th><th>Medium</th><th>Low</th></tr></thead>
            <tbody>
              {SEVS.map((s) => (
                <tr key={s}><th className={`sev-${s}`} style={{ textAlign: 'left', textTransform: 'capitalize' }}>{s}</th>
                  {['high', 'medium', 'low'].map((v) => <td key={v} className={d.matrix[s][v] ? 'hot' : 'muted'}>{d.matrix[s][v] ? <><span className={`prio prio-${PRIO[s][v]}`}>P{PRIO[s][v]}</span> {d.matrix[s][v]}</> : '·'}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ minWidth: 200 }}>
          <div className="small strong" style={{ marginBottom: 6 }}>Hosting countries</div>
          {h.countries.length === 0 ? <div className="muted small">Not known yet</div> : h.countries.slice(0, 8).map((c) => <div key={c.code} className="small">{country(c.code)}: {c.count}{c.high_risk && <span className="sev sev-high" style={{ marginLeft: 6 }}>high risk</span>}</div>)}
        </div>
        <div style={{ minWidth: 200 }}>
          <div className="small strong" style={{ marginBottom: 6 }}>Hosting providers</div>
          {h.providers.length === 0 ? <div className="muted small">Not known yet</div> : h.providers.slice(0, 8).map((p) => <div key={p.name} className="small">{p.name}: {p.count}</div>)}
        </div>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>System</th><th>Importance</th><th>Why</th><th>Hosted by</th><th className="num">Issues</th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.asset} className="static">
                <td className="mono small">{a.asset}{a.ip && a.ip !== a.asset && <div className="muted">{a.ip}</div>}</td>
                <td><span className={`sev sev-${a.value === 'high' ? 'high' : a.value === 'medium' ? 'medium' : 'info'}`}>{VALUE[a.value]}</span></td>
                <td className="small muted">{a.reasons.join('; ')}</td>
                <td className="small">{a.provider || '—'}{a.country && <div className={a.high_risk_country ? 'error' : 'muted'}>{country(a.country)}</div>}</td>
                <td className="num">{a.issues || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {d.assets.length > 12 && <p className="pad"><button className="btn ghost tiny" onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show all ${d.assets.length} systems`}</button></p>}
      <p className="muted small pad" style={{ paddingTop: 0 }}>Hosting network and country come from public internet routing data (Team Cymru).</p>
    </section>
  )
}
