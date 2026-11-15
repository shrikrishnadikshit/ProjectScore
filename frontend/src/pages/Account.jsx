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
      <PrivacyRights />
    </>
  )
}


function PrivacyRights() {
  const [confirming, setConfirming] = useState(false)
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  async function remove(e) {
    e.preventDefault(); setError(null)
    try { await api.deleteAccount(password); window.location.href = '/' } catch (err) { setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.') }
  }
  return (
    <section className="card form">
      <h2>Your data</h2>
      <p className="small">Download a copy of the personal data ProjectScore holds about you, or delete your account. See the <a href="/privacy">privacy policy</a>.</p>
      <div className="actions" style={{ justifyContent: 'flex-start' }}>
        <a className="btn ghost" href="/api/account/export" download>Download my data</a>
        {!confirming && <button type="button" className="btn ghost" onClick={() => setConfirming(true)}>Delete my account</button>}
      </div>
      {confirming && (
        <form onSubmit={remove} className="form" style={{ marginTop: 12 }}>
          <p className="small">This signs you out and permanently removes your name and email. Your organisation's portfolio stays. It cannot be undone.</p>
          <label>Enter your password to confirm<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button type="button" className="btn ghost" onClick={() => setConfirming(false)}>Cancel</button><button className="btn primary">Delete my account</button></div>
        </form>
      )}
    </section>
  )
}
