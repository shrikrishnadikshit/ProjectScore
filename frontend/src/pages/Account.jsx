import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

export default function Account() {
  const { user } = useOutletContext()
  const [form, setForm] = useState({ current: '', next: '', confirm: '' })
  const [message, setMessage] = useState(null)
  const [error, setError] = useState(null)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setError(null)
    setMessage(null)
    if (form.next !== form.confirm) return setError('The new passwords do not match.')
    try {
      await api.changePassword(form.current, form.next)
      setMessage('Password changed.')
      setForm({ current: '', next: '', confirm: '' })
    } catch (err) {
      setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.')
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Your account</h1>
          <p className="muted">{user.email} · {user.organization} · <span className="role">{user.role}</span></p>
        </div>
      </div>
      <form className="card form" onSubmit={submit}>
        <h2>Change password</h2>
        <label>Current password<input type="password" autoComplete="current-password" required value={form.current} onChange={set('current')} /></label>
        <label>New password (12+ characters)<input type="password" autoComplete="new-password" minLength={12} required value={form.next} onChange={set('next')} /></label>
        <label>Confirm new password<input type="password" autoComplete="new-password" minLength={12} required value={form.confirm} onChange={set('confirm')} /></label>
        {error && <p className="error">{error}</p>}
        {message && <p className="strong">{message}</p>}
        <div className="actions"><button className="btn primary">Change password</button></div>
      </form>
    </>
  )
}
