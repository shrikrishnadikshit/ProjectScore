import { useEffect, useState } from 'react'
import { Link, useOutletContext, useParams } from 'react-router-dom'
import { api, SEVERITY_ORDER } from '../api.js'

const TOOLS = [
  ['Gitleaks', 'Passwords, API keys and tokens left in the code'],
  ['OSV-Scanner', 'Third-party libraries with known vulnerabilities (CVEs)'],
  ['Bandit', 'Insecure patterns in Python code'],
]
const active = (s) => s === 'queued' || s === 'running'

function ReviewResults({ id }) {
  const [review, setReview] = useState(null)
  const [error, setError] = useState(null)
  const [tool, setTool] = useState('all')
  useEffect(() => {
    let timer
    const load = () => api.getCodeReview(id).then((r) => {
      setReview(r)
      if (active(r.status)) timer = setTimeout(load, 5000)
    }).catch((e) => setError(e.message))
    load()
    return () => clearTimeout(timer)
  }, [id])
  if (error) return <div className="card error">{error}</div>
  if (!review) return <div className="muted">Loading…</div>
  const results = review.results.filter((r) => tool === 'all' || r.tool === tool)
  const counts = SEVERITY_ORDER.map((s) => [s, review.summary.by_severity?.[s] || 0]).filter(([, n]) => n)
  return (
    <>
      <Link to="/code-reviews" className="back">← Code reviews</Link>
      <div className="page-head">
        <div>
          <h1>Code review: {review.name}</h1>
          <p className="muted">{review.source_type === 'git' ? review.source : 'Uploaded zip'} · {new Date(review.created_at).toLocaleString()}</p>
        </div>
      </div>
      {active(review.status) && <div className="banner">Review in progress. Most finish within a few minutes; this page updates by itself.</div>}
      {review.status === 'failed' && <div className="banner error">The review failed: {review.error}</div>}
      {review.summary.notes?.length > 0 && <div className="banner">{review.summary.notes.join('. ')}.</div>}
      {review.status === 'done' && (
        <section className="card table-card">
          <div className="section-head">
            <h2>Findings ({review.summary.total})</h2>
            <a className="btn small" href={`/api/code-reviews/${review.id}/sarif`} download title="SARIF 2.1.0, for GitHub code scanning, Azure DevOps and other tools">Download SARIF</a>
            <div className="chips">{counts.map(([s, n]) => <span key={s} className={`sev sev-${s}`}>{n} {s}</span>)}</div>
          </div>
          <div className="chips" style={{ padding: '0 20px 12px' }}>
            {['all', ...TOOLS.map(([t]) => t)].map((t) => (
              <button key={t} className={`btn tiny ${tool === t ? 'primary' : 'ghost'}`} onClick={() => setTool(t)}>
                {t === 'all' ? 'All tools' : `${t} (${review.summary.by_tool?.[t] || 0})`}
              </button>
            ))}
          </div>
          {results.length === 0 ? <p className="muted pad">No issues found{tool !== 'all' ? ` by ${tool}` : ''}.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Severity</th><th>Issue and fix</th><th>Where</th></tr></thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={i} className="static">
                      <td><span className={`sev sev-${r.severity}`}>{r.severity}</span><div className="muted small">{r.tool}</div></td>
                      <td>
                        <div className="strong">{r.title}</div>
                        {(r.cves?.length > 0 || r.cwe?.length > 0) && <div className="mono small">{[...(r.cves || []), ...(r.cwe || [])].join(', ')}</div>}
                        {r.detail && <div className="muted small">{r.detail}</div>}
                        {r.fix && <div className="small"><b>Fix:</b> {r.fix}</div>}
                      </td>
                      <td className="mono small">{r.file}{r.line ? `:${r.line}` : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
      <p className="muted small">Your code was deleted from our server as soon as the review finished. Only these findings are kept, with secret values hidden.</p>
    </>
  )
}

export default function CodeReviews() {
  const { user } = useOutletContext()
  const { reviewId } = useParams()
  const [reviews, setReviews] = useState([])
  const [mode, setMode] = useState('git')
  const [url, setUrl] = useState('')
  const [file, setFile] = useState(null)
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const isAdmin = user.role === 'admin' || user.role === 'owner'

  useEffect(() => {
    if (reviewId) return
    let timer
    const load = () => api.listCodeReviews().then((rs) => {
      setReviews(rs)
      if (rs.some((r) => active(r.status))) timer = setTimeout(load, 5000)
    }).catch((e) => setError(e.message))
    load()
    return () => clearTimeout(timer)
  }, [reviewId, busy])

  if (reviewId) return <ReviewResults id={reviewId} />

  const submit = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      if (mode === 'git') await api.startGitReview(url, confirm)
      else await api.uploadCodeReview(file, confirm)
      setUrl(''); setFile(null); setConfirm(false); e.target.reset()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Code reviews</h1>
          <p className="muted">Check your source code with free, widely used open-source scanners. The code is only read, never run, and is deleted as soon as the review finishes.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      <section className="card">
        <h2>What is checked</h2>
        <ul className="small">{TOOLS.map(([t, d]) => <li key={t}><b>{t}</b>: {d}</li>)}</ul>
      </section>
      {isAdmin ? (
        <section className="card">
          <h2>Start a review</h2>
          <form className="form" style={{ maxWidth: 'none' }} onSubmit={submit}>
            <div className="chips">
              <button type="button" className={`btn tiny ${mode === 'git' ? 'primary' : 'ghost'}`} onClick={() => setMode('git')}>Public Git link</button>
              <button type="button" className={`btn tiny ${mode === 'zip' ? 'primary' : 'ghost'}`} onClick={() => setMode('zip')}>Upload a zip</button>
            </div>
            {mode === 'git'
              ? <label>Repository link (GitHub, GitLab or Bitbucket)<input required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/your-org/your-app" /></label>
              : <label>Zip file (up to 50 MB)<input required type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0] || null)} /></label>}
            <label className="check"><input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />I confirm my organisation owns this code or is authorised to have it reviewed.</label>
            <div className="actions"><button className="btn primary" disabled={!confirm || busy}>{busy ? 'Starting…' : 'Start review'}</button></div>
            <p className="muted small">For private repositories, download the code as a zip and upload it. Up to 10 reviews a day per organisation.</p>
          </form>
        </section>
      ) : <div className="banner">Ask an admin in your organisation to start a code review.</div>}
      <section className="card table-card">
        <h2 style={{ padding: '20px 20px 0' }}>Reviews</h2>
        {reviews.length === 0 ? <p className="muted pad">No reviews yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Code</th><th>Started</th><th>Status</th><th className="num">Findings</th></tr></thead>
              <tbody>
                {reviews.map((r) => (
                  <tr key={r.id} onClick={() => { window.location.href = `/code-reviews/${r.id}` }}>
                    <td><Link to={`/code-reviews/${r.id}`} className="row-title">{r.name}</Link></td>
                    <td className="small muted">{new Date(r.created_at).toLocaleString()}</td>
                    <td><span className="role">{r.status}</span></td>
                    <td className="num">{r.status === 'done' ? r.summary.total : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
