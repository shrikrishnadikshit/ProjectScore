import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Incidents({ entityId }) {
  const [rows, setRows] = useState([])
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.listIncidents(entityId).then(setRows).catch(() => {})
  useEffect(() => { load() }, [entityId])
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function save(e) {
    e.preventDefault()
    setError(null)
    try { await api.recordIncident(entityId, form); setForm(null); load() } catch (err) { setError(err.message) }
  }

  return (
    <section className="card">
      <div className="section-head">
        <h2>Known incidents</h2>
        {!form && <button className="btn ghost tiny" onClick={() => setForm({ occurred_on: '', kind: 'breach', description: '', source_url: '' })}>Record an incident</button>}
      </div>
      <p className="muted small">Owner only. Real incidents at rated companies, used to test whether scores predict them.</p>
      {form && (
        <form className="form" onSubmit={save} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Date<input type="date" required value={form.occurred_on} onChange={set('occurred_on')} /></label>
            <label>Type
              <select value={form.kind} onChange={set('kind')}>
                {['breach', 'ransomware', 'outage', 'fraud', 'other'].map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </label>
          </div>
          <label>What happened<textarea rows={2} required value={form.description} onChange={set('description')} /></label>
          <label>Source link<input type="url" value={form.source_url} onChange={set('source_url')} placeholder="Optional" /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button type="button" className="btn ghost" onClick={() => setForm(null)}>Cancel</button><button className="btn primary">Save</button></div>
        </form>
      )}
      {rows.length > 0 && <ul className="small">{rows.map((i) => (
        <li key={i.id}>{i.occurred_on} · {i.kind}: {i.description}{i.score_before != null && <span className="muted"> (score before: {i.score_before})</span>}{i.source_url && <> · <a href={i.source_url} target="_blank" rel="noreferrer">source</a></>}</li>
      ))}</ul>}
    </section>
  )
}
