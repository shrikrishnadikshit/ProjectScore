import { Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function ApiKeys() {
  const [rows, setRows] = useState([])
  const [name, setName] = useState('')
  const [created, setCreated] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.listApiKeys().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  async function create(e) {
    e.preventDefault()
    setError(null)
    try { setCreated(await api.createApiKey(name)); setName(''); load() } catch (err) { setError(err.message) }
  }
  async function revoke(id) { await api.revokeApiKey(id); load() }

  const origin = window.location.origin
  return (
    <section className="card">
      <h2>API keys</h2>
      <p className="muted small">Read-only keys let your own systems (for example a SIEM, GRC tool or spreadsheet) fetch your portfolio, scores and findings. Send the key as <span className="mono">Authorization: Bearer ps_…</span>. Keys can read but never change anything. Every endpoint is listed in the <Link to="/api-docs">API docs</Link>.</p>
      {created && (
        <div className="banner">
          <div className="strong small">Copy this key now. It will not be shown again.</div>
          <div className="mono small key-box">{created.key}</div>
          <div className="muted small">Try it: <span className="mono">curl -H "Authorization: Bearer {created.prefix}…" {origin}/api/entities</span></div>
        </div>
      )}
      <form className="form-inline" onSubmit={create}>
        <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="Key name, for example SIEM" aria-label="Key name" />
        <button className="btn primary">Create key</button>
      </form>
      {error && <p className="error">{error}</p>}
      {rows.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Name</th><th>Key</th><th>Created</th><th>Last used</th><th></th></tr></thead>
            <tbody>
              {rows.map((k) => (
                <tr key={k.id} className="static">
                  <td>{k.name}</td>
                  <td className="mono small">{k.prefix}…</td>
                  <td className="small muted">{new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="small muted">{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'Never'}</td>
                  <td>{k.revoked ? <span className="role">Revoked</span> : <button className="btn ghost tiny" onClick={() => revoke(k.id)}>Revoke</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
