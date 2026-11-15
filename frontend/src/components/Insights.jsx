import { useEffect, useState } from 'react'
import { api } from '../api.js'

function ordinal(n) {
  const s = ['th', 'st', 'nd', 'rd'], v = n % 100
  return n + (s[(v - 20) % 10] || s[v] || s[0])
}

function Group({ label, g }) {
  if (!g) return null
  return (
    <div className="bench-row">
      <div className="small strong">{label}</div>
      {g.percentile == null
        ? <div className="muted small">{g.count} rated so far; comparison starts at {g.min_group}.</div>
        : <>
          <div className="bench-bar" aria-hidden="true"><span style={{ left: `${g.percentile}%` }} /></div>
          <div className="muted small">Better than {g.percentile}% of {g.count} companies ({ordinal(g.percentile)} percentile). Median score {g.median}.</div>
        </>}
    </div>
  )
}

export default function Insights({ entity, user, version }) {
  const [bench, setBench] = useState(null)
  const [industries, setIndustries] = useState([])
  const [editing, setEditing] = useState(false)
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const load = () => api.benchmark(entity.id).then(setBench).catch(() => setBench(null))
  useEffect(() => { load() }, [entity.id, version])
  useEffect(() => { if (editing) api.industries().then(setIndustries) }, [editing])

  async function changeIndustry(e) {
    await api.setIndustry(entity.id, e.target.value || null)
    setEditing(false)
    load()
  }

  const p = entity.patching
  return (
    <section className="overview">
      <div className="card">
        <div className="section-head">
          <h2>Compared with peers</h2>
          {isAdmin && !editing && <button className="btn ghost tiny" onClick={() => setEditing(true)}>{bench?.industry ? 'Change industry' : 'Set industry'}</button>}
        </div>
        {editing && (
          <select defaultValue={bench?.industry ?? ''} onChange={changeIndustry} aria-label="Industry">
            <option value="">No industry</option>
            {industries.map((i) => <option key={i} value={i}>{i}</option>)}
          </select>
        )}
        {bench?.platform ? <>
          {bench.industry ? <Group label={bench.industry} g={bench.industry_group} />
            : <p className="muted small">Set an industry to compare with similar companies.</p>}
          <Group label="All rated companies" g={bench.platform} />
        </> : <p className="muted small">Available after the first scan.</p>}
      </div>
      <div className="card">
        <h2>Patching speed</h2>
        {!p || (p.fixed === 0 && p.open === 0)
          ? <p className="muted small">No software vulnerabilities seen so far, so there is nothing to measure yet.</p>
          : <div className="stats">
            <div><div className="stat">{p.median_days_to_fix ?? 'n/a'}</div><div className="muted small">median days to fix ({p.fixed} fixed)</div></div>
            <div><div className="stat">{p.open}</div><div className="muted small">open now</div></div>
            <div><div className={`stat ${p.open_over_30_days ? 'error' : ''}`}>{p.open_over_30_days}</div><div className="muted small">open over 30 days</div></div>
          </div>}
        <p className="muted small">Measured from our weekly scans: when each vulnerability was first seen and when it disappeared.</p>
      </div>
    </section>
  )
}
