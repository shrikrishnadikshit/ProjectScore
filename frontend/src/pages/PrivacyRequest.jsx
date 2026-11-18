import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import PublicFooter from '../components/PublicFooter.jsx'

export default function PrivacyRequest() {
  const [facts, setFacts] = useState(null)
  const [form, setForm] = useState({ kind: '', email: '', name: '', details: '', website: '' })
  const [sent, setSent] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  useEffect(() => { api.privacyFacts().then(setFacts).catch(() => {}) }, [])
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function submit(e) {
    e.preventDefault(); setBusy(true); setError(null)
    try { await api.submitPrivacyRequest(form); setSent(true) } catch (err) { setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.') } finally { setBusy(false) }
  }

  return (
    <div className="public">
      <Link to="/" className="brand">ProjectScore</Link>
      <h1>Privacy request</h1>
      <p>Ask to see the personal data we hold about you, correct it, delete it, or stop us using it or emailing you. We reply within {facts?.answer_days || 30} days. See our <Link to="/privacy">privacy policy</Link> for what we hold and why.</p>
      {sent ? (
        <section className="card"><h2>Request received</h2><p>Thank you. We will reply to the email address you gave within {facts?.answer_days || 30} days. We may ask you to confirm it is your address before we act.</p></section>
      ) : (
        <section className="card">
          <form className="form" onSubmit={submit} style={{ maxWidth: 'none' }}>
            <label>What would you like us to do?
              <select required value={form.kind} onChange={set('kind')}>
                <option value="">Choose…</option>
                {Object.entries(facts?.kinds || {}).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
              </select>
            </label>
            <label>Your email address<input type="email" required value={form.email} onChange={set('email')} /></label>
            <label>Your name<input value={form.name} onChange={set('name')} placeholder="Optional" /></label>
            <label>Details<textarea rows={4} value={form.details} onChange={set('details')} placeholder="Optional. For example, which data is wrong, or where you received an email from us." /></label>
            <input type="text" tabIndex={-1} autoComplete="off" value={form.website} onChange={set('website')} aria-hidden="true" style={{ position: 'absolute', left: '-9999px' }} />
            {error && <p className="error">{error}</p>}
            <div className="actions"><button className="btn primary" disabled={busy}>{busy ? 'Sending…' : 'Send request'}</button></div>
          </form>
        </section>
      )}
      <p className="muted small">If you run a website and want us to stop scanning it, use the <Link to="/scanner">scanner opt-out</Link> instead.</p>
      <PublicFooter />
    </div>
  )
}
