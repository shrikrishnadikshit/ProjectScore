import PublicFooter from '../components/PublicFooter.jsx'
import { useState } from 'react'
import { api } from '../api.js'

export default function Scanner() {
  const [form, setForm] = useState({ domain: '', contact_email: '', organisation: '', reason: '', website: '' })
  const [sent, setSent] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.requestOptOut(form)
      setSent(true)
    } catch (err) {
      setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="public">
      <a href="/" className="brand">
        <span className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg>
        </span>
        ProjectScore
      </a>
      <h1>About the ProjectScore scanner</h1>
      <p>If you found <span className="mono">ProjectScore-Scanner</span> in your logs, this page explains what it is and how to opt out.</p>

      <section className="card">
        <h2>What it does</h2>
        <p>ProjectScore produces outside-in security ratings that help organisations understand the cyber risk of their suppliers and of themselves. To do this, the scanner looks only at information that any visitor to your website or any internet user could see.</p>
        <ul>
          <li>Public DNS records, such as SPF, DMARC, MTA-STS and DNSSEC.</li>
          <li>Public Certificate Transparency logs, to find your subdomains.</li>
          <li>One normal HTTPS request per host to read the certificate and response headers.</li>
          <li>Public threat-intelligence lists (abuse.ch, Spamhaus DROP, blocklist.de), to spot hosts that are serving malware or have been taken over.</li>
        </ul>
      </section>

      <section className="card">
        <h2>What it never does</h2>
        <ul>
          <li>No login attempts, exploitation, vulnerability probing or port sweeps.</li>
          <li>No high-volume traffic: each host gets a handful of requests at most once a day.</li>
          <li>No collection of personal data from your systems.</li>
        </ul>
        <p className="muted small">Requests identify themselves with the user agent <span className="mono">ProjectScore-Scanner/1.0 (+{window.location.origin}/scanner; passive security rating)</span>.</p>
      </section>

      <section className="card">
        <h2>Opt out of scanning</h2>
        {sent ? (
          <p className="strong">Thank you. We have received your request and will review it, normally within two working days. We may contact you to confirm that you are authorised to act for the domain.</p>
        ) : (
          <form className="form" onSubmit={submit} style={{ maxWidth: 'none' }}>
            <p className="muted small">Approved requests stop all scanning of the domain and its subdomains.</p>
            <div className="form-row">
              <label>Domain<input required value={form.domain} onChange={set('domain')} placeholder="example.com" /></label>
              <label>Your work email<input type="email" required value={form.contact_email} onChange={set('contact_email')} placeholder="security@example.com" /></label>
            </div>
            <label>Organisation<input value={form.organisation} onChange={set('organisation')} placeholder="Optional" /></label>
            <label>Anything else we should know<textarea rows={3} value={form.reason} onChange={set('reason')} /></label>
            <label className="hp" aria-hidden="true">Website<input tabIndex={-1} autoComplete="off" value={form.website} onChange={set('website')} /></label>
            {error && <p className="error">{error}</p>}
            <div className="actions"><button className="btn primary" disabled={busy}>{busy ? 'Sending…' : 'Request opt-out'}</button></div>
          </form>
        )}
      </section>

      <PublicDispute />
      <PublicFooter />
    </div>
  )
}

function PublicDispute() {
  const [form, setForm] = useState({ domain: '', contact_email: '', organisation: '', reason: '', website: '' })
  const [sent, setSent] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.publicDispute(form)
      setSent(true)
    } catch (err) {
      setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h2>Dispute a finding about your organisation</h2>
      {sent ? (
        <p className="strong">Thank you. We will review your dispute, normally within five working days, and may contact you for evidence. If we agree, the finding is removed and the rating is recalculated.</p>
      ) : (
        <form className="form" onSubmit={submit} style={{ maxWidth: 'none' }}>
          <p className="muted small">If a finding is wrong, for example a host is not yours or an issue has been fixed, tell us and we will check it.</p>
          <div className="form-row">
            <label>Your domain<input required value={form.domain} onChange={set('domain')} placeholder="example.com" /></label>
            <label>Your work email<input type="email" required value={form.contact_email} onChange={set('contact_email')} placeholder="security@example.com" /></label>
          </div>
          <label>Organisation<input value={form.organisation} onChange={set('organisation')} placeholder="Optional" /></label>
          <label>What is wrong, and why<textarea rows={4} required minLength={10} value={form.reason} onChange={set('reason')} placeholder="Which finding or host, and what the correct position is." /></label>
          <label className="hp" aria-hidden="true">Website<input tabIndex={-1} autoComplete="off" value={form.website} onChange={set('website')} /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button className="btn primary" disabled={busy}>{busy ? 'Sending…' : 'Send dispute'}</button></div>
        </form>
      )}
    </section>
  )
}
