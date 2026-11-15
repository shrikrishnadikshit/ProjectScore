import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import AddEntityForm from '../components/AddEntityForm.jsx'
import { GradeBadge } from '../components/Grade.jsx'

const TIER_LABEL = { 1: 'Tier 1', 2: 'Tier 2', 3: 'Tier 3' }

export default function Portfolio() {
  const [entities, setEntities] = useState(null)
  const [error, setError] = useState(null)
  const [adding, setAdding] = useState(false)
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState('score')
  const navigate = useNavigate()

  useEffect(() => {
    api.listEntities().then(setEntities).catch((e) => setError(e.message))
  }, [])

  const stats = useMemo(() => {
    if (!entities) return null
    const scored = entities.filter((e) => e.score != null)
    const avg = scored.length ? Math.round(scored.reduce((a, e) => a + e.score, 0) / scored.length) : null
    const atRisk = scored.filter((e) => e.grade === 'D' || e.grade === 'F').length
    return { total: entities.length, avg, atRisk, unscored: entities.length - scored.length }
  }, [entities])

  const rows = useMemo(() => {
    if (!entities) return []
    const q = query.trim().toLowerCase()
    const filtered = entities.filter((e) => !q || e.name.toLowerCase().includes(q) || e.primary_domain.includes(q))
    const by = {
      score: (a, b) => (a.score ?? 9999) - (b.score ?? 9999),
      name: (a, b) => a.name.localeCompare(b.name),
      tier: (a, b) => a.tier - b.tier || (a.score ?? 9999) - (b.score ?? 9999),
    }[sort]
    return [...filtered].sort(by)
  }, [entities, query, sort])

  if (error) return <div className="card error">Could not load the portfolio: {error}</div>
  if (!entities) return <div className="muted">Loading…</div>

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vendor portfolio</h1>
          <p className="muted">Outside-in security ratings for the companies you monitor.</p>
        </div>
        {!adding && <button className="btn primary" onClick={() => setAdding(true)}>Add company</button>}
      </div>

      {adding && (
        <AddEntityForm onCancel={() => setAdding(false)} onCreated={(e) => navigate(`/entities/${e.id}?scanning=1`)} />
      )}

      <section className="tiles">
        <div className="tile"><div className="tile-label">Companies monitored</div><div className="tile-value">{stats.total}</div></div>
        <div className="tile"><div className="tile-label">Average score</div><div className="tile-value">{stats.avg ?? '—'}</div></div>
        <div className="tile"><div className="tile-label">Grade D or F</div><div className={`tile-value ${stats.atRisk ? 'warn' : ''}`}>{stats.atRisk}</div></div>
        <div className="tile"><div className="tile-label">Awaiting first scan</div><div className="tile-value">{stats.unscored}</div></div>
      </section>

      {entities.length === 0 ? (
        <div className="card empty">
          <h2>No companies yet</h2>
          <p className="muted">Add a vendor or your own organisation by its domain to get its first rating.</p>
          {!adding && <button className="btn primary" onClick={() => setAdding(true)}>Add your first company</button>}
        </div>
      ) : (
        <div className="card table-card">
          <div className="table-tools">
            <input className="search" placeholder="Search by name or domain" value={query} onChange={(e) => setQuery(e.target.value)} />
            <label className="sort">Sort by
              <select value={sort} onChange={(e) => setSort(e.target.value)}>
                <option value="score">Lowest score first</option>
                <option value="tier">Tier</option>
                <option value="name">Name</option>
              </select>
            </label>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th>Company</th><th>Tier</th><th className="num">Score</th><th>Grade</th><th>Last scan</th></tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} onClick={() => navigate(`/entities/${e.id}`)}>
                    <td>
                      <Link to={`/entities/${e.id}`} className="row-title">{e.name}</Link>
                      <div className="muted small">{e.primary_domain}</div>
                    </td>
                    <td><span className={`tier tier-${e.tier}`}>{TIER_LABEL[e.tier]}</span></td>
                    <td className="num strong">{e.score ?? '—'}</td>
                    <td><GradeBadge grade={e.grade} size="sm" /></td>
                    <td className="muted small">{e.scanned_at ? new Date(e.scanned_at).toLocaleString() : 'Not scanned'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  )
}
