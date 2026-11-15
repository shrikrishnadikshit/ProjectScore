import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'

export default function AddVendorButton({ vendor }) {
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  if (vendor.in_portfolio) {
    return <button className="btn ghost tiny" onClick={() => navigate(`/entities/${vendor.entity_id}`)}>{vendor.grade ? `Grade ${vendor.grade}` : 'Open'}</button>
  }
  async function add() {
    setBusy(true); setError(null)
    try {
      const e = await api.createEntity({ name: vendor.name, primary_domain: vendor.domain, tier: 3 })
      await api.startScan(e.id).catch(() => {})
      navigate(`/entities/${e.id}?scanning=1`)
    } catch (err) { setError(err.message); setBusy(false) }
  }
  return (
    <>
      <button className="btn ghost tiny" onClick={add} disabled={busy}>{busy ? 'Adding…' : 'Add and rate'}</button>
      {error && <div className="error small">{error}</div>}
    </>
  )
}
