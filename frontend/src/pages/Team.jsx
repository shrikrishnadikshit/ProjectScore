import { useEffect, useState } from 'react'
import { Navigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'
import ApiKeys from '../components/ApiKeys.jsx'

function TempPassword({ result, onClose }) {
  const [copied, setCopied] = useState(false)
  const text = `Sign in at ${window.location.origin}\nEmail: ${result.email}\nTemporary password: ${result.temporary_password}`
  return (
    <div className="callout">
      <div className="strong">Temporary password for {result.email}</div>
      <p className="small">Share it privately (not in a group chat). It is shown only once. They should change it from their account page after signing in.</p>
      <code>{result.temporary_password}</code>
      <div className="actions">
        <button className="btn ghost tiny" onClick={() => navigator.clipboard?.writeText(text).then(() => setCopied(true))}>
          {copied ? 'Copied' : 'Copy sign-in details'}
        </button>
        <button className="btn ghost tiny" onClick={onClose}>Done</button>
      </div>
    </div>
  )
}

export default function Team() {
  const { user } = useOutletContext()
  const isOwner = user.role === 'owner'
  const [users, setUsers] = useState(null)
  const [orgs, setOrgs] = useState([])
  const [form, setForm] = useState({ email: '', name: '', role: 'member', organization: user.organization })
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const load = () => Promise.all([api.listUsers(), api.listOrganizations()])
    .then(([u, o]) => { setUsers(u); setOrgs(o) })
    .catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  if (user.role !== 'admin' && !isOwner) return <Navigate to="/" replace />

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function add(e) {
    e.preventDefault()
    setError(null)
    try {
      const created = await api.addUser({ ...form, name: form.name || null })
      setResult(created)
      setAdding(false)
      setForm({ email: '', name: '', role: 'member', organization: form.organization })
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  async function act(fn) {
    setError(null)
    try {
      const out = await fn()
      if (out?.temporary_password) setResult(out)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Team</h1>
          <p className="muted">{isOwner
            ? 'You manage users for every client organisation. Each organisation sees only its own portfolio.'
            : `People who can sign in to ${user.organization}.`}</p>
        </div>
        {!adding && <button className="btn primary" onClick={() => setAdding(true)}>Add user</button>}
      </div>

      {result && <TempPassword result={result} onClose={() => setResult(null)} />}
      {error && <div className="banner error">{error}</div>}

      {adding && (
        <form className="card form" onSubmit={add}>
          <h2>Add a user</h2>
          <div className="form-row">
            <label>Email<input type="email" required value={form.email} onChange={set('email')} /></label>
            <label>Name<input value={form.name} onChange={set('name')} placeholder="Optional" /></label>
          </div>
          <div className="form-row">
            <label>Organisation
              {isOwner ? (
                <>
                  <input list="org-options" required value={form.organization} onChange={set('organization')} />
                  <datalist id="org-options">{orgs.map((o) => <option key={o} value={o} />)}</datalist>
                </>
              ) : <input value={user.organization} disabled />}
            </label>
            <label>Role
              <select value={form.role} onChange={set('role')}>
                <option value="member">Member: views and manages the portfolio</option>
                <option value="admin">Admin: also manages users</option>
              </select>
            </label>
          </div>
          {isOwner && <p className="muted small">Type a new organisation name to set up a new client.</p>}
          <div className="actions">
            <button type="button" className="btn ghost" onClick={() => setAdding(false)}>Cancel</button>
            <button className="btn primary">Add user</button>
          </div>
        </form>
      )}

      <div className="card table-card">
        <div className="table-scroll">
          <table>
            <thead><tr><th>User</th>{isOwner && <th>Organisation</th>}<th>Role</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {(users ?? []).map((u) => (
                <tr key={u.id} className="static">
                  <td><div className="strong">{u.name || u.email}</div>{u.name && <div className="muted small">{u.email}</div>}</td>
                  {isOwner && <td className="small">{u.organization}</td>}
                  <td><span className="role">{u.role}</span></td>
                  <td>{u.active ? <span className="small muted">Active</span> : <span className="status-off">Deactivated</span>}</td>
                  <td>
                    {u.id !== user.id && u.role !== 'owner' && (
                      <div className="row-actions">
                        <button className="btn ghost tiny" onClick={() => act(() => api.resetPassword(u.id))}>Reset password</button>
                        <button className="btn ghost tiny" onClick={() => act(() => api.updateUser(u.id, { active: !u.active }))}>
                          {u.active ? 'Deactivate' : 'Reactivate'}
                        </button>
                      </div>
                    )}
                    {u.id === user.id && <span className="muted small">You</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <ApiKeys />
    </>
  )
}
