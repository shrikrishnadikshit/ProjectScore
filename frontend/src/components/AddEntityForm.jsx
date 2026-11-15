import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function AddEntityForm({ onCreated, onCancel }) {
  const [form, setForm] = useState({ name: '', primary_domain: '', industry: '', tier: 3 })
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const [industries, setIndustries] = useState([])
  useEffect(() => { api.industries().then(setIndustries).catch(() => {}) }, [])

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const entity = await api.createEntity({ ...form, tier: Number(form.tier), industry: form.industry || null })
      await api.startScan(entity.id)
      onCreated(entity)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card form" onSubmit={submit}>
      <h2>Add a company</h2>
      <label>Company name<input required value={form.name} onChange={set('name')} placeholder="Acme Ltd" /></label>
      <label>Primary domain<input required value={form.primary_domain} onChange={set('primary_domain')} placeholder="acme.com" /></label>
      <div className="form-row">
        <label>Industry
          <select value={form.industry} onChange={set('industry')}>
            <option value="">Choose…</option>
            {industries.map((i) => <option key={i} value={i}>{i}</option>)}
          </select>
        </label>
        <label>Vendor tier
          <select value={form.tier} onChange={set('tier')}>
            <option value={1}>Tier 1 (critical)</option>
            <option value={2}>Tier 2 (high)</option>
            <option value={3}>Tier 3 (standard)</option>
          </select>
        </label>
      </div>
      {error && <p className="error">{error}</p>}
      <p className="muted small">Adding a company starts a passive, non-intrusive scan of its public internet footprint.</p>
      <div className="actions">
        <button type="button" className="btn ghost" onClick={onCancel}>Cancel</button>
        <button className="btn primary" disabled={busy}>{busy ? 'Adding…' : 'Add and scan'}</button>
      </div>
    </form>
  )
}
