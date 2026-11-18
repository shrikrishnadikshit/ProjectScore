import PublicFooter from '../components/PublicFooter.jsx'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../api.js'

const OPTIONS = [['yes', 'Yes'], ['partial', 'Partly'], ['no', 'No'], ['na', 'N/A']]

export default function VendorQuestionnaire() {
  const { token } = useParams()
  const [data, setData] = useState(null)
  const [answers, setAnswers] = useState({})
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)
  const [drafts, setDrafts] = useState({})
  const [files, setFiles] = useState([])
  const [drafting, setDrafting] = useState(false)
  useEffect(() => {
    api.publicQuestionnaire(token).then((d) => { setData(d); setAnswers(d.answers || {}); setDrafts(d.drafts || {}) }).catch((e) => setError(e.message))
  }, [token])

  if (error && !data) return <div className="public"><div className="card error">This link is not valid or has expired. Please ask the sender for a new one.</div></div>
  if (!data) return <div className="public"><p className="muted">Loading…</p></div>
  const done = data.status === 'submitted' || data.status === 'reviewed'
  const answered = data.questions.filter((q) => answers[q.id]?.answer).length
  const set = (id, k, v) => setAnswers({ ...answers, [id]: { ...answers[id], [k]: v } })

  async function save(submit) {
    setBusy(true); setError(null); setMsg(null)
    try {
      const r = await api.savePublicQuestionnaire(token, answers, submit)
      if (submit) setData({ ...data, status: r.status })
      else setMsg('Saved. You can close this page and come back to the same link later.')
    } catch (e) { setError(e.message.charAt(0).toUpperCase() + e.message.slice(1) + '.') }
    setBusy(false)
  }

  async function draft(e) {
    e.preventDefault(); setDrafting(true); setError(null); setMsg(null)
    try {
      const r = await api.draftFromDocuments(token, files)
      setDrafts(r.drafts); setData({ ...data, documents: r.documents, ai: { ...data.ai, runs_left: r.runs_left } }); setFiles([])
      const n = data.questions.filter((q) => r.drafts[q.id]?.answer).length
      setMsg(`Suggested answers are ready for ${n} of ${data.questions.length} questions. Check each one and press "Use" to accept it.`)
    } catch (err) { setError(err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.') }
    setDrafting(false)
  }
  const applyDraft = (q) => {
    const d = drafts[q.id]
    const quote = d.evidence ? `From ${d.document || 'your documents'}: "${d.evidence}"` : ''
    setAnswers({ ...answers, [q.id]: { answer: d.answer, comment: answers[q.id]?.comment || quote } })
  }
  const applyAll = () => {
    const next = { ...answers }
    for (const q of data.questions) {
      const d = drafts[q.id]
      if (d?.answer && !next[q.id]?.answer) next[q.id] = { answer: d.answer, comment: d.evidence ? `From ${d.document || 'your documents'}: "${d.evidence}"` : '' }
    }
    setAnswers(next)
  }
  const draftCount = data.questions.filter((q) => drafts[q.id]?.answer).length
  const sections = [...new Set(data.questions.map((q) => q.section))]
  return (
    <div className="public">
      <span className="brand"><span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg></span>ProjectScore</span>
      <h1>Security questionnaire for {data.company}</h1>
      {done ? <div className="card"><p className="strong">Thank you. Your answers have been sent to {data.requested_by}.</p></div> : <>
        <p>{data.requested_by} has asked you to answer {data.questions.length} questions about your security practices. It takes about 15 minutes. Answer honestly: {data.requested_by} may compare your answers with publicly visible information. Add a comment wherever it helps.</p>
        {data.ai?.available && (
          <section className="card">
            <h2>Save time: draft answers from your documents</h2>
            <p className="small">Upload your security policy, ISO 27001 statement of applicability, SOC 2 report or similar (PDF or text, up to 3 files of 10 MB). AI reads them and suggests an answer for each question with the passage it relied on. Nothing is filled in until you accept it, and you stay responsible for every answer. The files are read once and not kept.</p>
            <form className="form" onSubmit={draft} style={{ maxWidth: 'none' }}>
              <input type="file" multiple accept=".pdf,.txt,.md,application/pdf,text/plain" onChange={(e) => setFiles([...e.target.files].slice(0, 3))} />
              <div className="actions" style={{ justifyContent: 'flex-start' }}>
                <button className="btn primary" disabled={drafting || !files.length || !data.ai.runs_left}>{drafting ? 'Reading your documents… (up to a minute)' : 'Suggest answers'}</button>
                {draftCount > 0 && <button type="button" className="btn ghost" onClick={applyAll}>Use all suggestions for unanswered questions ({draftCount})</button>}
              </div>
              <p className="muted small">{data.ai.runs_left} uploads left.{data.documents?.length ? ` Read so far: ${data.documents.map((d) => d.name).join(', ')}.` : ''}</p>
            </form>
          </section>
        )}
        {sections.map((s) => (
          <section key={s} className="card">
            <h2>{s}</h2>
            {data.questions.filter((q) => q.section === s).map((q) => (
              <fieldset key={q.id} className="qa-row">
                <legend className="small">{q.text}</legend>
                <div className="qa-options">
                  {OPTIONS.map(([v, label]) => (
                    <label key={v} className={`qa-opt ${answers[q.id]?.answer === v ? 'on' : ''}`}>
                      <input type="radio" name={q.id} value={v} checked={answers[q.id]?.answer === v} onChange={() => set(q.id, 'answer', v)} />{label}
                    </label>
                  ))}
                </div>
                {drafts[q.id] && (
                  <div className="small qa-draft">
                    <span className="chip">Suggested: {drafts[q.id].answer ? OPTIONS.find(([v]) => v === drafts[q.id].answer)?.[1] : 'Not found in your documents'}</span>
                    {drafts[q.id].answer && <span className="muted"> ({drafts[q.id].confidence} confidence)</span>}
                    {drafts[q.id].evidence && <div className="muted">"{drafts[q.id].evidence}"{drafts[q.id].document ? ` (${drafts[q.id].document})` : ''}</div>}
                    {drafts[q.id].answer && answers[q.id]?.answer !== drafts[q.id].answer && <button type="button" className="btn ghost" onClick={() => applyDraft(q)}>Use</button>}
                  </div>
                )}
                <input className="qa-comment-input small" placeholder="Comment (optional)" value={answers[q.id]?.comment ?? ''} onChange={(e) => set(q.id, 'comment', e.target.value)} />
              </fieldset>
            ))}
          </section>
        ))}
        <div className="card">
          <p className="small muted">{answered} of {data.questions.length} answered.</p>
          {error && <p className="error">{error}</p>}
          {msg && <p className="small">{msg}</p>}
          <div className="actions">
            <button className="btn ghost" disabled={busy} onClick={() => save(false)}>Save and finish later</button>
            <button className="btn primary" disabled={busy || answered < data.questions.length} onClick={() => save(true)}>Submit answers</button>
          </div>
        </div>
      </>}
      <PublicFooter />
    </div>
  )
}
