import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import AddVendorButton from '../components/AddVendorButton.jsx'

export default function FourthParties() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [category, setCategory] = useState('all')
  useEffect(() => { api.fourthParties().then(setData).catch((e) => setError(e.message)) }, [])
  if (error) return <div className="card error">{error}</div>
  if (!data) return <div className="muted">Loading…</div>
  const categories = [...new Set(data.vendors.map((v) => v.category))].sort()
  const rows = data.vendors.filter((v) => category === 'all' || v.category === category)
  const shared = data.vendors.filter((v) => v.used_by.length > 1).length
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Supply chain</h1>
          <p className="muted">The services your vendors rely on (your fourth parties), found automatically in their public DNS. When many of your vendors depend on one service, an outage or breach there hits you several times over.</p>
        </div>
      </div>
      <section className="tiles">
        <div className="tile"><div className="tile-label">Vendors checked</div><div className="tile-value">{data.companies_checked} of {data.companies_total}</div></div>
        <div className="tile"><div className="tile-label">Fourth parties found</div><div className="tile-value">{data.vendors.length}</div></div>
        <div className="tile"><div className="tile-label">Shared by 2 or more vendors</div><div className={`tile-value ${shared ? 'warn' : ''}`}>{shared}</div></div>
      </section>
      {data.companies_checked < data.companies_total && <div className="banner">Vendors are checked during each scan. {data.companies_total - data.companies_checked} of your companies have not been checked yet.</div>}
      <section className="card table-card">
        <div className="table-tools">
          <label className="sort">Category
            <select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="all">All</option>
              {categories.map((c) => <option key={c}>{c}</option>)}
            </select>
          </label>
        </div>
        {rows.length === 0 ? <p className="muted pad">Nothing found yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Service</th><th>Category</th><th>Used by</th><th></th></tr></thead>
              <tbody>
                {rows.map((v) => (
                  <tr key={v.name} className="static">
                    <td><div className="strong">{v.name}</div><div className="mono small muted">{v.domain}</div></td>
                    <td className="small">{v.category}</td>
                    <td className="small"><b>{v.used_by.length}</b> {v.used_by.length === 1 ? 'vendor' : 'vendors'}: {v.used_by.slice(0, 6).map((u, i) => <span key={u.id}>{i > 0 && ', '}<Link to={`/entities/${u.id}`}>{u.name}</Link></span>)}{v.used_by.length > 6 && ` and ${v.used_by.length - 6} more`}</td>
                    <td><AddVendorButton vendor={v} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
