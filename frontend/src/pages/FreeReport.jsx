import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, FACTOR_LABELS } from '../api.js'
import { GradeBadge, ScoreGauge, gradeClass } from '../components/Grade.jsx'

const Brand = () => (
  <a href="/" className="brand">
    <span className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg>
    </span>
    ProjectScore
  </a>
)

export default function FreeReport() {
  const [params, setParams] = useSearchParams()
  const token = params.get('r')
  return (
    <div className="public">
      <Brand />
      <h1>Free security rating for your organisation</h1>
      {token ? <Report token={token} /> : <RequestForm onToken={(t) => setParams({ r: t })} />}
    </div>
  )
}

function RequestForm({ onToken }) {
  const [form, setForm] = useState({ name: '', contact_email: '', domain: '', organisation: '', website: '' })
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onToken((await api.requestFreeReport(form)).token)
    } catch (err) {
      setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.')
      setBusy(false)
    }
  }

  return (
    <>
      <p>See how your organisation looks to an attacker, an insurer or a customer doing due diligence. We check only what is publicly visible: email and DNS settings, encryption, website security, exposed services and public threat lists. Nothing is installed and nothing intrusive is sent to your systems.</p>
      <section className="card">
        <form className="form" onSubmit={submit} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Your name<input value={form.name} onChange={set('name')} autoComplete="name" /></label>
            <label>Organisation<input value={form.organisation} onChange={set('organisation')} autoComplete="organization" /></label>
          </div>
          <div className="form-row">
            <label>Company domain<input required value={form.domain} onChange={set('domain')} placeholder="example.com" /></label>
            <label>Work email at that domain<input type="email" required value={form.contact_email} onChange={set('contact_email')} placeholder="you@example.com" autoComplete="email" /></label>
          </div>
          <label className="hp" aria-hidden="true">Website<input tabIndex={-1} autoComplete="off" value={form.website} onChange={set('website')} /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button className="btn primary" disabled={busy}>{busy ? 'Starting…' : 'Get my free rating'}</button></div>
          <p className="muted small">One report per organisation, for your own domain only. We will keep your details to follow up about the report. See <a href="/scanner">how our scanner works</a>.</p>
        </form>
      </section>
    </>
  )
}

function Report({ token }) {
  const [rep, setRep] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let timer
    const load = () => api.getFreeReport(token).then((r) => {
      setRep(r)
      if (r.status === 'scanning') timer = setTimeout(load, 4000)
    }).catch((e) => setError(e.message))
    load()
    return () => clearTimeout(timer)
  }, [token])

  if (error) return <div className="card error">This report link is not valid or has expired. <a href="/free-report">Request a new one</a>.</div>
  if (!rep) return <p className="muted">Loading…</p>
  if (rep.status === 'scanning') return (
    <section className="card"><p className="strong">Rating {rep.domain}…</p><p className="muted">This usually takes two to four minutes. Keep this page open; it updates by itself. You can also bookmark it and come back.</p></section>
  )
  if (rep.status === 'failed') return <div className="card error">We could not rate {rep.domain}: {rep.message}.</div>

  const factors = Object.entries(rep.factors).sort((a, b) => a[1].score - b[1].score)
  const total = Object.values(rep.counts).reduce((a, b) => a + b, 0)
  return (
    <>
      <section className="card score-card">
        <ScoreGauge score={rep.score} grade={rep.grade} />
        <div className="score-meta">
          <GradeBadge grade={rep.grade} size="lg" />
          <div>
            <div className="strong">{rep.domain}</div>
            <div className="muted small">Rated {new Date(rep.rated_at).toLocaleDateString()} on a scale of 300 to 900.</div>
            {rep.coverage != null && rep.coverage < 1 && <div className="muted small">Based on {Math.round(rep.coverage * 100)}% of rating factors.</div>}
          </div>
        </div>
      </section>
      <section className="card">
        <h2>Risk factors</h2>
        <div className="factors">
          {factors.map(([k, f]) => (
            <div key={k} className="factor">
              <div className="factor-head"><span>{FACTOR_LABELS[k] ?? k}</span><GradeBadge grade={f.grade} size="sm" /></div>
              <div className="bar"><div className={`bar-fill ${gradeClass(f.grade)}`} style={{ width: `${f.score}%` }} /></div>
            </div>
          ))}
        </div>
      </section>
      <section className="card">
        <h2>{total} issue{total === 1 ? '' : 's'} found</h2>
        <div className="chips">{Object.entries(rep.counts).filter(([, n]) => n).map(([s, n]) => <span key={s} className={`sev sev-${s}`}>{n} {s}</span>)}</div>
        {rep.top_issues.length > 0 && <ul>{rep.top_issues.map((i) => <li key={i.title}><span className={`sev sev-${i.severity}`}>{i.severity}</span> {i.title}</li>)}</ul>}
        <p className="muted small" style={{ marginTop: 16 }}>The full report lists every affected host and IP address, with fix guidance, history and continuous monitoring of your suppliers. Reply to our follow-up email or contact us to see it.</p>
      </section>
    </>
  )
}
