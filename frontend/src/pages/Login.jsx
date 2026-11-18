import PublicFooter from '../components/PublicFooter.jsx'
import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Login({ onSignedIn }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [providers, setProviders] = useState([])
  const [challenge, setChallenge] = useState(() => new URLSearchParams(window.location.search).get('mfa'))
  const [code, setCode] = useState('')
  useEffect(() => {
    api.ssoProviders().then(setProviders).catch(() => {})
    const code = new URLSearchParams(window.location.search).get('sso_error')
    if (code) {
      setError({
        no_account: 'There is no ProjectScore account for that email address. Ask your administrator to invite you.',
        cancelled: 'Sign-in was cancelled.',
        expired: 'The sign-in took too long. Please try again.',
      }[code] ?? 'Single sign-on failed. Please try again or use your password.')
      window.history.replaceState(null, '', window.location.pathname)
    }
  }, [])

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      if (challenge) {
        const u = await api.mfaLogin(challenge, code)
        window.history.replaceState(null, '', window.location.pathname)
        return onSignedIn(u)
      }
      const r = await api.login(email, password)
      if (r.mfa_required) { setChallenge(r.challenge); setCode(''); return }
      onSignedIn(r)
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
        {challenge ? <>
          <label>Code from your authenticator app<input inputMode="numeric" autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} /></label>
          <p className="muted small">Lost your phone? Enter one of your recovery codes instead.</p>
        </> : <>
          <label>Email<input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        </>}
        {error && <p className="error">{error}</p>}
        <button className="btn primary" disabled={busy}>{busy ? 'Signing in…' : challenge ? 'Verify' : 'Sign in'}</button>
        {challenge && <button type="button" className="link-btn small" onClick={() => { setChallenge(null); setError(null) }}>Start again</button>}
        {providers.length > 0 && <>
          <div className="divider muted small"><span>or</span></div>
          {providers.map((p) => <a key={p.id} className="btn ghost sso-btn" href={`/api/auth/sso/${p.id}/start`}>Sign in with {p.label}</a>)}
        </>}
        <p className="muted small">Access is by invitation. Ask your administrator for an account.</p>
        <p className="muted small">Not a customer yet? <a href="/free-report">Get a free rating for your organisation</a>.</p>
        <p className="muted small"><a href="/scanner">About our scanner and opting out</a></p>
      </form>
      <PublicFooter />
    </div>
  )
}
