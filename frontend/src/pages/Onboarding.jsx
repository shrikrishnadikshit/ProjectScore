import { useEffect, useState } from 'react'
import { Link, useNavigate, useOutletContext, useParams } from 'react-router-dom'
import { api } from '../api.js'

const STAGE = { intake: 'Intake', assessment: 'Assessment', review: 'Review', approved: 'Approved', conditional: 'Approved with conditions', rejected: 'Rejected' }
const LEVEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' }
const OPTION = {
  none: 'None', internal: 'Internal business data', personal: 'Personal data', sensitive_personal: 'Sensitive personal data',
  financial: 'Financial data', health: 'Health data', small: 'Under 1,000', medium: '1,000 to 100,000', large: 'Over 100,000',
  read: 'Read only', write: 'Can change data', admin: 'Administrator', network: 'Network or VPN connection',
  low: 'Little effect', high: 'Serious', critical: 'Business stops', yes: 'Yes', no: 'No',
}
const ACTIONS = {
  intake: [['start_assessment', 'Start assessment'], ['reject', 'Reject']],
  assessment: [['submit_for_review', 'Send for approval'], ['approve', 'Approve'], ['approve_with_conditions', 'Approve with conditions'], ['reject', 'Reject']],
  review: [['approve', 'Approve'], ['approve_with_conditions', 'Approve with conditions'], ['reject', 'Reject']],
  approved: [['reopen', 'Reassess now']], conditional: [['reopen', 'Reassess now']], rejected: [['reopen', 'Reopen']],
}
const NEEDS_NOTE = new Set(['approve_with_conditions', 'reject'])
const CHECK = { met: ['ok', '✓'], not_met: ['error', '✗'], pending: ['muted', '…'] }

export default function Onboarding() {
  const { id } = useParams()
  return id ? <Detail id={id} /> : <List />
}

function List() {
  const { user } = useOutletContext()
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [entities, setEntities] = useState([])
  const [pick, setPick] = useState('')
  const [error, setError] = useState(null)
  useEffect(() => {
    api.listOnboarding().then(setData).catch((e) => setError(e.message))
    api.listEntities().then((d) => setEntities(Array.isArray(d) ? d : d.items || [])).catch(() => {})
  }, [])
  if (error && !data) return <div className="card error">{error}</div>
  if (!data) return <div className="muted">Loading…</div>
  const started = new Set(data.items.map((i) => i.entity_id))
  const available = entities.filter((e) => !started.has(e.id))

  async function start(e) {
    e.preventDefault(); setError(null)
    try { const ob = await api.startOnboarding(Number(pick), {}); navigate(`/onboarding/${ob.id}`) } catch (err) { setError(err.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vendor onboarding</h1>
          <p className="muted">Bring each new vendor through intake, a risk tier, an assessment that fits the tier, and an approval. Approved vendors come back for reassessment on a schedule: every 6 months for tier 1, 12 for tier 2 and 24 for tier 3.</p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      {isAdmin && (
        <section className="card">
          <form className="form inline-form" onSubmit={start} style={{ maxWidth: 'none' }}>
            <label>Start onboarding for
              <select value={pick} onChange={(e) => setPick(e.target.value)} required>
                <option value="">Choose a company in your portfolio…</option>
                {available.map((e) => <option key={e.id} value={e.id}>{e.name} ({e.primary_domain})</option>)}
              </select>
            </label>
            <div className="actions"><button className="btn primary" disabled={!pick}>Start</button></div>
          </form>
          <p className="muted small">Add the company to your <Link to="/">portfolio</Link> first if it is not listed.</p>
        </section>
      )}
      <section className="tiles">
        {['intake', 'assessment', 'review'].map((s) => <div key={s} className="tile"><div className="tile-label">{STAGE[s]}</div><div className="tile-value">{data.items.filter((i) => i.stage === s).length}</div></div>)}
        <div className="tile"><div className="tile-label">Reassessment due</div><div className={`tile-value ${data.due ? 'warn' : ''}`}>{data.due}</div></div>
      </section>
      <section className="card table-card">
        <h2>Vendors</h2>
        {data.items.length === 0 ? <p className="muted pad">No vendors are being onboarded yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Company</th><th>Stage</th><th>Inherent risk</th><th>Tier</th><th>Next review</th></tr></thead>
              <tbody>
                {data.items.map((i) => (
                  <tr key={i.id} className="static">
                    <td><Link to={`/onboarding/${i.id}`} className="row-title">{i.name}</Link><div className="muted small mono">{i.domain}</div></td>
                    <td className="small">{STAGE[i.stage]}</td>
                    <td className="small">{i.level ? `${LEVEL[i.level]} (${i.inherent_score})` : <span className="muted">Intake not finished</span>}</td>
                    <td>{i.tier ? <span className={`tier tier-${i.tier}`}>Tier {i.tier}</span> : '—'}</td>
                    <td className="small">{i.next_review ? <span className={i.review_due ? 'error' : ''}>{i.next_review}{i.review_due ? ' (due)' : ''}</span> : '—'}</td>
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

function Detail({ id }) {
  const { user } = useOutletContext()
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const [ob, setOb] = useState(null)
  const [intake, setIntake] = useState({})
  const [pending, setPending] = useState(null)
  const [note, setNote] = useState('')
  const [tier, setTier] = useState('')
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const load = (d) => { setOb(d); setIntake(d.intake || {}); setTier(d.tier ? String(d.tier) : '') }
  useEffect(() => { api.getOnboarding(id).then(load).catch((e) => setError(e.message)) }, [id])
  if (error && !ob) return <div className="card error">{error}</div>
  if (!ob) return <div className="muted">Loading…</div>
  const locked = !isAdmin || ['approved', 'conditional', 'rejected'].includes(ob.stage)

  async function saveIntake(e) {
    e.preventDefault(); setError(null); setMsg(null)
    try { load(await api.saveIntake(id, intake)); setMsg('Intake saved.') } catch (err) { setError(err.message) }
  }
  async function act(e) {
    e.preventDefault(); setError(null); setMsg(null)
    try {
      const t = tier && Number(tier) !== ob.tier ? Number(tier) : null
      load(await api.onboardingAction(id, pending, note || null, t)); setPending(null); setNote('')
    } catch (err) { setError(err.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <p className="small"><Link to="/onboarding">← Vendor onboarding</Link></p>
          <h1>{ob.name}</h1>
          <p className="muted"><span className="mono">{ob.domain}</span> · {STAGE[ob.stage]}{ob.next_review ? ` · next review ${ob.next_review}` : ''} · <Link to={`/entities/${ob.entity_id}`}>Security rating and questionnaires</Link></p>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      {msg && <div className="banner">{msg}</div>}

      <section className="tiles">
        <div className="tile"><div className="tile-label">Inherent risk</div><div className="tile-value">{ob.level ? `${LEVEL[ob.level]}` : '—'}</div><div className="muted small">{ob.inherent_score != null ? `${ob.inherent_score} of 100, before any controls` : 'Finish the intake'}</div></div>
        <div className="tile"><div className="tile-label">Tier</div><div className="tile-value">{ob.tier ? `Tier ${ob.tier}` : '—'}</div><div className="muted small">{ob.tier ? `Reassessed every ${{ 1: 6, 2: 12, 3: 24 }[ob.tier]} months` : 'Set from the intake'}</div></div>
        <div className="tile"><div className="tile-label">Residual risk</div><div className="tile-value">{ob.residual ? LEVEL[ob.residual.level] : '—'}</div><div className="muted small">{ob.residual ? `${ob.residual.score} of 100, after its controls (rating ${ob.residual.inputs.rating}${ob.residual.inputs.questionnaire != null ? `, questionnaire ${ob.residual.inputs.questionnaire}%` : ''})` : 'Needs the intake and a first scan'}</div></div>
        <div className="tile"><div className="tile-label">Stage</div><div className="tile-value">{STAGE[ob.stage]}</div></div>
      </section>

      <section className="card">
        <h2>Business context</h2>
        <p className="muted small">What this vendor will do for you. The answers set the inherent risk and tier, which decide how deep the assessment goes and which questionnaire questions the vendor gets.</p>
        <form className="form" onSubmit={saveIntake} style={{ maxWidth: 'none' }}>
          {ob.questions.map((q) => (
            <label key={q.key}>{q.text}
              <select disabled={locked} value={intake[q.key] || ''} onChange={(e) => setIntake({ ...intake, [q.key]: e.target.value })}>
                <option value="">Choose…</option>
                {q.options.map((o) => <option key={o} value={o}>{OPTION[o] || o}</option>)}
              </select>
            </label>
          ))}
          {!locked && <div className="actions"><button className="btn primary">Save intake</button></div>}
        </form>
      </section>

      {ob.tier && (
        <section className="card">
          <h2>Tier {ob.tier} assessment</h2>
          <p className="muted small">Required: {ob.requirements.join('; ')}.</p>
          <div className="fw-list">
            {ob.checks.map((c) => (
              <div key={c.check} className="fw-row small" style={{ padding: '8px 0' }}>
                <span className={CHECK[c.state][0]}>{CHECK[c.state][1]}</span> <strong>{c.check}</strong> <span className="muted">{c.detail}</span>
              </div>
            ))}
          </div>
          <p className="muted small">Send the questionnaire from the <Link to={`/entities/${ob.entity_id}`}>company page</Link>. It will ask only the questions that fit this vendor's tier and business context.</p>
        </section>
      )}

      {ob.decision_note && <section className="card"><h2>Decision note</h2><p>{ob.decision_note}</p></section>}

      {isAdmin && (
        <section className="card">
          <h2>Next step</h2>
          <div className="actions" style={{ justifyContent: 'flex-start', flexWrap: 'wrap' }}>
            {(ACTIONS[ob.stage] || []).map(([a, label]) => (
              <button key={a} className={`btn ${pending === a ? 'primary' : 'ghost'}`} onClick={() => setPending(a)}>{label}</button>
            ))}
          </div>
          {pending && (
            <form className="form" onSubmit={act} style={{ maxWidth: 'none', marginTop: 12 }}>
              {pending.startsWith('approve') && (
                <label>Tier
                  <select value={tier} onChange={(e) => setTier(e.target.value)}>
                    {[1, 2, 3].map((t) => <option key={t} value={t}>Tier {t}{t === ob.tier ? ' (suggested)' : ''}</option>)}
                  </select>
                </label>
              )}
              <label>{NEEDS_NOTE.has(pending) ? 'Why (required)' : 'Note (optional)'}
                <textarea rows={2} value={note} required={NEEDS_NOTE.has(pending)} onChange={(e) => setNote(e.target.value)}
                  placeholder={pending === 'approve_with_conditions' ? 'For example: enforce DMARC within 30 days' : ''} />
              </label>
              <div className="actions"><button type="button" className="btn ghost" onClick={() => setPending(null)}>Cancel</button><button className="btn primary">Confirm</button></div>
            </form>
          )}
        </section>
      )}

      <section className="card">
        <h2>History</h2>
        {ob.history.length === 0 ? <p className="muted small">Nothing yet.</p> : (
          <ul className="small">
            {[...ob.history].reverse().map((h, i) => (
              <li key={i}><span className="muted">{new Date(h.at).toLocaleString()}</span> · {h.by}: <strong>{h.action}</strong>{h.note ? ` (${h.note})` : ''}</li>
            ))}
          </ul>
        )}
      </section>
    </>
  )
}
