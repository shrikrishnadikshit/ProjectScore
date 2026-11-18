import { useEffect, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'
import Integrations from '../components/Integrations.jsx'

let regionNames
try { regionNames = new Intl.DisplayNames(['en'], { type: 'region' }) } catch { regionNames = null }
const COUNTRIES = ['IN', 'US', 'GB', 'DE', 'FR', 'NL', 'BE', 'IE', 'IT', 'ES', 'SE', 'NO', 'DK', 'FI', 'CH', 'AT', 'PL', 'PT',
  'AE', 'SA', 'QA', 'KW', 'BH', 'OM', 'SG', 'MY', 'ID', 'TH', 'PH', 'VN', 'JP', 'KR', 'AU', 'NZ', 'CA', 'MX', 'BR', 'AR',
  'CL', 'CO', 'ZA', 'NG', 'KE', 'EG', 'IL', 'TR', 'LK', 'BD', 'NP', 'PK']
  .map((c) => [c, regionNames?.of(c) || c]).sort((a, b) => a[1].localeCompare(b[1]))

export default function Settings() {
  const { user } = useOutletContext()
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const [s, setS] = useState(null)
  const [form, setForm] = useState(null)
  const [msg, setMsg] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { api.getOrgSettings().then((d) => { setS(d); setForm({ country: d.country, currency: d.currency, cost: d.breach_cost_overridden ? d.breach_cost_usd_m : '' }) }).catch((e) => setError(e.message)) }, [])
  if (!s || !form) return error ? <div className="card error">{error}</div> : <div className="muted">Loading…</div>

  async function save(e) {
    e.preventDefault(); setError(null); setMsg(null)
    try {
      const d = await api.setOrgSettings({ country: form.country, currency: form.currency, breach_cost_usd_m: form.cost === '' ? null : Number(form.cost) })
      setS(d); setMsg('Settings saved.')
    } catch (err) { setError(err.message) }
  }
  const options = COUNTRIES.some(([c]) => c === form.country) ? COUNTRIES : [[form.country, regionNames?.of(form.country) || form.country], ...COUNTRIES]

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Organisation settings</h1>
          <p className="muted">Where your organisation is based. This sets the regulations shown first, the default currency, the local cost of a breach used in money estimates, and what counts as "hosted abroad".</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      {msg && <div className="banner">{msg}</div>}
      <section className="card">
        <form className="form" onSubmit={save}>
          <label>Home country
            <select disabled={!isAdmin} value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })}>
              {options.map(([c, name]) => <option key={c} value={c}>{name}</option>)}
            </select>
          </label>
          <label>Default currency
            <select disabled={!isAdmin} value={form.currency} onChange={(e) => setForm({ ...form, currency: e.target.value })}>
              {s.currencies.map((c) => <option key={c}>{c}</option>)}
            </select>
          </label>
          <label>Average cost of a data breach in your market (millions of US dollars)
            <input disabled={!isAdmin} type="number" min="0.01" step="0.01" value={form.cost} onChange={(e) => setForm({ ...form, cost: e.target.value })}
              placeholder={`Leave blank to use ${s.breach_cost_overridden ? 'the published average' : `${s.breach_cost_usd_m} (${s.breach_cost_source})`}`} />
          </label>
          {isAdmin ? <div className="actions"><button className="btn primary">Save</button></div> : <p className="muted small">Only admins can change these settings.</p>}
        </form>
      </section>
      <Thresholds isAdmin={isAdmin} />
      <SecurityPolicy isAdmin={isAdmin} />
      <Integrations isAdmin={isAdmin} />
    </>
  )
}

function SecurityPolicy({ isAdmin }) {
  const [p, setP] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { api.orgSecurity().then(setP).catch(() => {}) }, [])
  if (!p) return null
  async function toggle(e) {
    setError(null)
    try { setP(await api.setOrgSecurity(e.target.checked)) } catch (err) { setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.') }
  }
  return (
    <section className="card">
      <h2>Sign-in security</h2>
      <label className="check"><input type="checkbox" disabled={!isAdmin} checked={p.require_mfa} onChange={toggle} />Require two-step login for everyone in the organisation</label>
      <p className="muted small">Each person sets it up from Your account. Until they do, they can only reach the setup page.</p>
      {error && <p className="error">{error}</p>}
      {isAdmin && <p className="small"><Link to="/audit">Open the audit log</Link> to see who changed what.</p>}
    </section>
  )
}

const SEVS = ['critical', 'high', 'medium', 'low']

function Thresholds({ isAdmin }) {
  const [p, setP] = useState(null)
  const [msg, setMsg] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { api.orgPreferences().then(setP).catch(() => {}) }, [])
  if (!p) return null
  async function save(e) {
    e.preventDefault(); setMsg(null); setError(null)
    try { setP(await api.setOrgPreferences(p)); setMsg('Saved.') } catch (err) { setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.') }
  }
  const box = (k, label) => <label className="check"><input type="checkbox" disabled={!isAdmin} checked={p[k]} onChange={(e) => setP({ ...p, [k]: e.target.checked })} />{label}</label>
  return (
    <section className="card">
      <h2>Monitoring and fix deadlines</h2>
      <form className="form" onSubmit={save} style={{ maxWidth: 'none' }}>
        <label>Rescan your companies every
          <select disabled={!isAdmin} value={p.rescan_days} onChange={(e) => setP({ ...p, rescan_days: Number(e.target.value) })}>
            {[1, 3, 7].map((d) => <option key={d} value={d}>{d === 1 ? 'day' : `${d} days`}</option>)}
          </select>
        </label>
        <label>Alert when a score falls by at least (points)
          <input type="number" min="5" max="300" disabled={!isAdmin} value={p.score_drop} onChange={(e) => setP({ ...p, score_drop: Number(e.target.value) })} />
        </label>
        {box('alert_grade_change', 'Alert when the grade gets worse')}
        {box('alert_new_critical', 'Alert on new critical issues')}
        {box('alert_new_high', 'Alert on new high-severity issues')}
        <p className="small strong" style={{ marginTop: 8 }}>Days allowed to fix an issue</p>
        <div className="form-row">
          {SEVS.map((s) => <label key={s} style={{ textTransform: 'capitalize' }}>{s}<input type="number" min="1" max="730" disabled={!isAdmin} value={p.sla_days[s]} onChange={(e) => setP({ ...p, sla_days: { ...p.sla_days, [s]: Number(e.target.value) } })} /></label>)}
        </div>
        {error && <p className="error">{error}</p>}
        {msg && <p className="small ok">{msg}</p>}
        {isAdmin && <div className="actions"><button className="btn primary">Save</button></div>}
      </form>
    </section>
  )
}
