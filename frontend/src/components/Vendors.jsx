import { useEffect, useState } from 'react'
import { api } from '../api.js'
import AddVendorButton from './AddVendorButton.jsx'

export default function Vendors({ entityId, entityName, version }) {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => { api.entityVendors(entityId).then(setData).catch(() => setData({ vendors: [] })) }, [entityId, version])
  const refresh = async () => {
    setBusy(true)
    try { setData(await api.entityVendors(entityId, true)) } catch { /* keep the old list */ }
    setBusy(false)
  }
  if (!data) return null
  return (
    <section className="card table-card">
      <div className="section-head">
        <div>
          <h2>{entityName}'s vendors ({data.vendors.length})</h2>
          <p className="muted small">Services this company relies on, found automatically in its public DNS records. They are your fourth parties: a breach at one of them can reach you through {entityName}.</p>
        </div>
        <button className="btn ghost small-btn" onClick={refresh} disabled={busy}>{busy ? 'Checking…' : 'Check again'}</button>
      </div>
      {data.vendors.length === 0 ? <p className="muted pad">No vendors detected yet{data.detected_at ? '' : '; they are found during each scan'}.</p> : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Vendor</th><th>Used for</th><th>How we know</th><th></th></tr></thead>
            <tbody>
              {data.vendors.map((v) => (
                <tr key={v.name} className="static">
                  <td><div className="strong">{v.name}</div><div className="mono small muted">{v.domain}</div></td>
                  <td className="small">{v.category}</td>
                  <td className="small">
                    {v.evidence.slice(0, open === v.name ? 5 : 1).map((e, i) => (
                      <div key={i}>{e.what}<span className="mono muted"> · {e.record}</span></div>
                    ))}
                    {v.evidence.length > 1 && open !== v.name && <button className="btn ghost tiny" onClick={() => setOpen(v.name)}>+{v.evidence.length - 1} more</button>}
                  </td>
                  <td><AddVendorButton vendor={v} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
