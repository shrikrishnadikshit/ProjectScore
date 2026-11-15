import { useEffect, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

const NUMBER_RULES = ['min_score', 'max_critical', 'max_priority1', 'max_ransomware', 'max_days_since_scan']
const BOOL_RULES = ['require_certificate', 'no_high_risk_hosting']
const TIERS = ['1', '2', '3']

export default function Policy() {
  const { user } = useOutletContext()
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const [policy, setPolicy] = useState(null)
  const [draft, setDraft] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const load = () => Promise.all([api.getPolicy(), api.policyCompliance()]).then(([p, c]) => { setPolicy(p); setResult(c) }).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])
  if (error && !policy) return <div className="card error">{error}</div>
  if (!policy || !result) return <div className="muted">Loading…</div>

  const set = (tier, key, value) => setDraft({ ...draft, [tier]: { ...draft[tier], [key]: value } })
  async function save() {
    setError(null)
    try {
      const rules = Object.fromEntries(TIERS.map((t) => [t, Object.fromEntries(Object.entries(draft[t]).map(([k, v]) => [k, v === '' ? null : v]))]))
      await api.setPolicy(rules); setDraft(null); setNotice('Policy saved.'); load()
    } catch (e) { setError(e.message) }
  }
  const rules = draft || policy.rules

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vendor policy</h1>
          <p className="muted">Your minimum security requirements for each vendor tier, and which vendors currently fall short. Set a company's tier on the portfolio.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      {notice && <div className="banner">{notice}</div>}

      <section className="tiles">
        <div className="tile"><div className="tile-label">Meet the policy</div><div className="tile-value">{result.compliant} of {result.total}</div></div>
        <div className="tile"><div className="tile-label">Fall short</div><div className={`tile-value ${result.total - result.compliant ? 'warn' : ''}`}>{result.total - result.compliant}</div></div>
      </section>

      <section className="card table-card">
        <h2 style={{ padding: '20px 20px 0' }}>Vendors</h2>
        {result.companies.length === 0 ? <p className="muted pad">No companies yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Company</th><th>Tier</th><th className="num">Score</th><th>Policy</th></tr></thead>
              <tbody>
                {result.companies.map((c) => (
                  <tr key={c.entity_id} className="static">
                    <td><Link to={`/entities/${c.entity_id}`} className="row-title">{c.name}</Link></td>
                    <td className="small">Tier {c.tier}</td>
                    <td className="num">{c.score ?? '—'}</td>
                    <td className="small">{c.compliant ? <span className="ok">Meets policy</span> : c.breaches.map((b) => <div key={b.rule}><span className="error">✗</span> {b.label}: <span className="muted">{b.detail}</span></div>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card table-card">
        <div className="section-head">
          <div><h2>Requirements by tier</h2>{policy.is_default && <p className="muted small">These are suggested defaults. Adjust them to match your own policy.</p>}</div>
          {isAdmin && !draft && <button className="btn ghost" onClick={() => setDraft(JSON.parse(JSON.stringify(policy.rules)))}>Edit</button>}
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Rule</th>{TIERS.map((t) => <th key={t}>Tier {t}</th>)}</tr></thead>
            <tbody>
              {NUMBER_RULES.map((k) => (
                <tr key={k} className="static">
                  <td className="small">{policy.labels[k]}</td>
                  {TIERS.map((t) => <td key={t}>{draft
                    ? <input type="number" step={k === 'max_ransomware' ? '0.05' : '1'} min="0" style={{ width: 90 }} value={rules[t][k] ?? ''} onChange={(e) => set(t, k, e.target.value === '' ? '' : Number(e.target.value))} placeholder="no limit" />
                    : <span className="small">{rules[t][k] ?? <span className="muted">no limit</span>}</span>}</td>)}
                </tr>
              ))}
              {BOOL_RULES.map((k) => (
                <tr key={k} className="static">
                  <td className="small">{policy.labels[k]}</td>
                  {TIERS.map((t) => <td key={t}>{draft
                    ? <input type="checkbox" checked={!!rules[t][k]} onChange={(e) => set(t, k, e.target.checked)} />
                    : <span className="small">{rules[t][k] ? 'Yes' : <span className="muted">No</span>}</span>}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {draft && <div className="actions pad"><button className="btn ghost" onClick={() => setDraft(null)}>Cancel</button><button className="btn primary" onClick={save}>Save policy</button></div>}
      </section>
    </>
  )
}
