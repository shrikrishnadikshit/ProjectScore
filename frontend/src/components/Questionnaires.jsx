import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

const STATUS = { sent: 'Sent', in_progress: 'In progress', submitted: 'Submitted', reviewed: 'Reviewed' }

export default function Questionnaires({ entityId, user }) {
  const [rows, setRows] = useState([])
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(null)
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const load = () => api.listQuestionnaires(entityId).then(setRows).catch(() => {})
  useEffect(() => { load() }, [entityId])

  async function send(e) {
    e.preventDefault()
    setError(null)
    try {
      const q = await api.sendQuestionnaire(entityId, form)
      setForm(null)
      await load()
      copy(q)
    } catch (err) { setError(err.message) }
  }
  function copy(q) {
    const url = window.location.origin + q.link_path
    navigator.clipboard?.writeText(url).then(() => setCopied(q.id)).catch(() => setCopied(null))
  }

  return (
    <section className="card table-card">
      <div className="section-head">
        <h2>Security questionnaires</h2>
        {isAdmin && !form && <button className="btn ghost" onClick={() => setForm({ recipient_email: '', recipient_name: '' })}>Send questionnaire</button>}
      </div>
      {form && (
        <form className="form pad" onSubmit={send} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Vendor contact email<input type="email" required value={form.recipient_email} onChange={(e) => setForm({ ...form, recipient_email: e.target.value })} /></label>
            <label>Contact name<input value={form.recipient_name} onChange={(e) => setForm({ ...form, recipient_name: e.target.value })} placeholder="Optional" /></label>
          </div>
          <p className="muted small">The vendor answers 24 questions through a private link, without an account. You get a link to share; it is also emailed when email is set up. Their answers are checked against what our scans see.</p>
          {error && <p className="error">{error}</p>}
          <div className="actions">
            <button type="button" className="btn ghost" onClick={() => setForm(null)}>Cancel</button>
            <button className="btn primary">Create link</button>
          </div>
        </form>
      )}
      {rows.length === 0 && !form ? <p className="muted pad">None sent yet.</p> : rows.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Sent to</th><th>Status</th><th>Progress</th><th className="num">Score</th><th></th></tr></thead>
            <tbody>
              {rows.map((q) => (
                <tr key={q.id} className="static">
                  <td className="small">{q.recipient_name && <div>{q.recipient_name}</div>}{q.recipient_email}<div className="muted">{new Date(q.created_at).toLocaleDateString()}</div></td>
                  <td><span className="role">{STATUS[q.status]}</span></td>
                  <td className="small muted">{q.answered} of {q.total} answered</td>
                  <td className="num strong">{q.score != null ? `${q.score}%` : ''}</td>
                  <td>
                    <div className="row-actions">
                      {(q.status === 'submitted' || q.status === 'reviewed') && <Link className="btn ghost tiny" to={`/questionnaires/${q.id}`}>View answers</Link>}
                      {(q.status === 'sent' || q.status === 'in_progress') && <button className="btn ghost tiny" onClick={() => copy(q)}>{copied === q.id ? 'Link copied' : 'Copy link'}</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
