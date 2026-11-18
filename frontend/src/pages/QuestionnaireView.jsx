import { useEffect, useState } from 'react'
import { Link, useOutletContext, useParams } from 'react-router-dom'
import { api } from '../api.js'

const LABEL = { yes: 'Yes', partial: 'Partly', no: 'No', na: 'N/A' }

export default function QuestionnaireView() {
  const { id } = useParams()
  const { user } = useOutletContext()
  const [q, setQ] = useState(null)
  const [note, setNote] = useState('')
  const [error, setError] = useState(null)
  useEffect(() => { api.getQuestionnaire(id).then((r) => { setQ(r); setNote(r.reviewer_note || '') }).catch((e) => setError(e.message)) }, [id])
  if (error) return <div className="card error">{error}</div>
  if (!q) return <p className="muted">Loading…</p>

  const flagged = new Set(q.contradictions.map((c) => c.question))
  const sections = [...new Set(q.questions.map((x) => x.section))]
  async function review() { setQ(await api.reviewQuestionnaire(id, note)) }

  return (
    <>
      <Link to={`/entities/${q.entity_id}`} className="back">← Back to company</Link>
      <div className="page-head">
        <div>
          <h1>Questionnaire answers</h1>
          <p className="muted">From {q.recipient_name ? `${q.recipient_name}, ` : ''}{q.recipient_email} · submitted {new Date(q.submitted_at).toLocaleDateString()} · {q.score}% of controls in place</p>
          {q.tailored && <p className="muted small">Tailored to this vendor's tier and business context: {q.total} questions.{q.documents?.length ? ` The vendor used AI to draft answers from ${q.documents.length} of its own document${q.documents.length > 1 ? 's' : ''} and confirmed each answer.` : ''}</p>}
          {!q.tailored && q.documents?.length > 0 && <p className="muted small">The vendor used AI to draft answers from {q.documents.length} of its own document{q.documents.length > 1 ? 's' : ''} and confirmed each answer.</p>}
        </div>
      </div>
      {q.contradictions.length > 0 && (
        <section className="card banner-card">
          <h2>{q.contradictions.length} answer{q.contradictions.length > 1 ? 's' : ''} contradicted by our scans</h2>
          {q.contradictions.map((c) => (
            <div key={c.question} className="contra">
              <div className="strong small">Answered "Yes": {c.text}</div>
              <ul>{c.findings.map((f, i) => <li key={i} className="small"><span className={`sev sev-${f.severity}`}>{f.severity}</span> {f.title} <span className="mono muted">{f.asset}</span></li>)}</ul>
              {c.more > 0 && <div className="muted small">and {c.more} more</div>}
            </div>
          ))}
        </section>
      )}
      {sections.map((s) => (
        <section key={s} className="card">
          <h2>{s}</h2>
          {q.questions.filter((x) => x.section === s).map((x) => {
            const a = q.answers[x.id] || {}
            return (
              <div key={x.id} className="qa-row">
                <div className="small">{x.text}</div>
                <div className={`qa-answer ans-${a.answer} ${flagged.has(x.id) ? 'flagged' : ''}`}>{LABEL[a.answer] ?? 'No answer'}{flagged.has(x.id) ? ' (contradicted)' : ''}</div>
                {a.comment && <div className="muted small qa-comment">{a.comment}</div>}
              </div>
            )
          })}
        </section>
      ))}
      {(user.role === 'admin' || user.role === 'owner') && (
        <section className="card form" style={{ maxWidth: 'none' }}>
          <h2>Review</h2>
          <label>Notes for your team<textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} /></label>
          <div className="actions"><button className="btn primary" onClick={review}>{q.status === 'reviewed' ? 'Update review' : 'Mark as reviewed'}</button></div>
        </section>
      )}
    </>
  )
}
