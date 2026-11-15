import { useState } from 'react'
import { api } from '../api.js'

export default function Login({ onSignedIn }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onSignedIn(await api.login(email, password))
    } catch (err) {
      setError(err.message.charAt(0).toUpperCase() + err.message.slice(1))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="card form login" onSubmit={submit}>
        <div className="brand login-brand">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="26" height="26"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </span>
          ProjectScore
        </div>
        <h2>Sign in</h2>
        <label>Email<input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {error && <p className="error">{error}</p>}
        <button className="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p className="muted small">Access is by invitation. Ask your administrator for an account.</p>
      </form>
    </div>
  )
}
