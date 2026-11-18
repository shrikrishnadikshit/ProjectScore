import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

export default function ProductSearch() {
  const [q, setQ] = useState('')
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [sug, setSug] = useState([])
  useEffect(() => { api.productSuggestions().then(setSug).catch(() => {}) }, [])

  async function run(term) {
    const t = (term ?? q).trim()
    if (t.length < 2) return
    setQ(t); setBusy(true); setError(null)
    try { setRes(await api.productSearch(t)) } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  return (
    <section className="card">
      <h2>Which vendors run…</h2>
      <p className="muted small">When a new flaw is announced in a product, type its name to see which of your vendors show signs of using it: software their servers disclose, products named in CVEs on their systems, services they rely on and who hosts them.</p>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); run() }} style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input className="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="For example: MOVEit, Citrix, nginx, Okta, jQuery" style={{ flex: '1 1 260px' }} />
        <button className="btn primary" disabled={busy || q.trim().length < 2}>{busy ? 'Searching…' : 'Search'}</button>
      </form>
      {sug.length > 0 && !res && (
        <p className="small" style={{ marginTop: 8 }}><span className="muted">Seen most across your vendors: </span>
          {sug.slice(0, 10).map((s, i) => <span key={s.name}>{i > 0 && ', '}<button type="button" className="link-button" onClick={() => run(s.name)}>{s.name}</button> <span className="muted">({s.vendors})</span></span>)}
        </p>
      )}
      {error && <p className="error">{error}</p>}
      {res && (
        res.total === 0 ? <p className="small" style={{ marginTop: 12 }}>None of your vendors show signs of <strong>{res.query}</strong>. Outside-in scans cannot see everything, so for a critical flaw also ask tier 1 vendors directly.</p> : (
          <div className="table-scroll" style={{ marginTop: 12 }}>
            <p className="small"><strong>{res.total}</strong> vendor{res.total === 1 ? '' : 's'} show signs of <strong>{res.query}</strong>.</p>
            <table>
              <thead><tr><th>Vendor</th><th>Tier</th><th>Why it matched</th></tr></thead>
              <tbody>
                {res.vendors.map((v) => (
                  <tr key={v.entity_id} className="static">
                    <td><Link to={`/entities/${v.entity_id}`} className="row-title">{v.name}</Link><div className="muted small mono">{v.domain}</div></td>
                    <td className="small">{v.tier ? `Tier ${v.tier}` : '—'}</td>
                    <td className="small">{v.matches.map((m, i) => <div key={i}><span className="muted">{m.source}:</span> {m.what}{m.where ? <span className="muted mono"> on {m.where}</span> : null}</div>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </section>
  )
}
