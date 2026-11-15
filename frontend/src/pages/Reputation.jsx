import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useOutletContext, useParams } from 'react-router-dom'
import { api } from '../api.js'
import './reputation.css'

const SOURCE_LABELS = {
  news: 'News', hackernews: 'Hacker News', bluesky: 'Bluesky', reddit: 'Reddit', apple: 'App Store',
  import: 'Imported', manual: 'Added by hand',
}
const STATUS_LABELS = { new: 'New', seen: 'Seen', replied: 'Replied', ignored: 'Ignored' }

function when(iso) {
  if (!iso) return 'never'
  const d = new Date(iso)
  const mins = Math.round((Date.now() - d.getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  if (mins < 60 * 24) return `${Math.round(mins / 60)} h ago`
  return d.toLocaleDateString()
}

function ScoreBadge({ score, size = 'large' }) {
  const band = score == null ? 'none' : score >= 70 ? 'good' : score >= 45 ? 'fair' : 'poor'
  return (
    <div className={`rep-score rep-score-${band} rep-score-${size}`} title="Reputation score, 0 to 100">
      {score == null ? '–' : score}
    </div>
  )
}

function Trend({ daily }) {
  const w = 760, h = 150, pad = 22
  const max = Math.max(1, ...daily.map((d) => d.positive + d.neutral + d.negative))
  const bw = (w - 2 * pad) / daily.length
  const y = (v) => ((h - 2 * pad) * v) / max
  return (
    <svg className="rep-trend" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="Mentions per day by sentiment">
      <line x1={pad} x2={w - pad} y1={h - pad} y2={h - pad} className="history-grid" />
      <text x={2} y={pad} className="history-axis">{max}</text>
      {daily.map((d, i) => {
        const x = pad + i * bw + 1
        let base = h - pad
        return (
          <g key={d.date}>
            <title>{`${new Date(d.date).toLocaleDateString()}: ${d.positive} positive, ${d.neutral} neutral, ${d.negative} negative`}</title>
            {['negative', 'neutral', 'positive'].map((k) => {
              const hh = y(d[k])
              base -= hh
              return hh > 0 ? <rect key={k} x={x} y={base} width={Math.max(1, bw - 2)} height={hh} className={`rep-bar-${k}`} /> : null
            })}
          </g>
        )
      })}
      <text x={pad} y={h - 6} className="history-axis">{new Date(daily[0].date).toLocaleDateString()}</text>
      <text x={w - pad} y={h - 6} textAnchor="end" className="history-axis">Today</text>
    </svg>
  )
}

function SentimentPill({ label }) {
  return <span className={`rep-pill rep-pill-${label}`}>{label}</span>
}

function Stars({ n }) {
  if (!n) return null
  return <span className="rep-stars" aria-label={`${n} of 5 stars`}>{'★'.repeat(n)}<span className="muted">{'★'.repeat(5 - n)}</span></span>
}

// ------------------------------------------------------------------ brand form
function BrandForm({ config, initial, entities, onSave, onCancel, saving }) {
  const [f, setF] = useState(() => ({
    name: '', keywords: '', exclude: '', apple_app_id: '', apple_country: 'us', google_place_id: '',
    search_query: '', reply_contact: '', entity_id: '',
    sources: config.sources.filter((s) => s.available && s.key !== 'reddit').map((s) => s.key),
    ...(initial ? {
      ...initial, keywords: initial.keywords.join(', '), exclude: initial.exclude.join(', '),
      apple_app_id: initial.apple_app_id || '', google_place_id: initial.google_place_id || '',
      search_query: initial.search_query || '', reply_contact: initial.reply_contact || '', entity_id: initial.entity_id ?? '',
    } : {}),
  }))
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const toggle = (k) => setF({ ...f, sources: f.sources.includes(k) ? f.sources.filter((s) => s !== k) : [...f.sources, k] })
  const split = (v) => v.split(',').map((s) => s.trim()).filter(Boolean)

  function submit(e) {
    e.preventDefault()
    onSave({
      name: f.name, keywords: split(f.keywords), exclude: split(f.exclude), sources: f.sources,
      apple_app_id: f.apple_app_id || null, apple_country: f.apple_country || 'us', google_place_id: f.google_place_id || null,
      search_query: f.search_query || null, reply_contact: f.reply_contact || null,
      entity_id: f.entity_id === '' ? null : Number(f.entity_id),
    })
  }

  return (
    <form className="form rep-form" onSubmit={submit}>
      <div className="form-row">
        <label>Brand, product or person
          <input required minLength={2} maxLength={120} value={f.name} onChange={set('name')} placeholder="e.g. Acme Bank" />
        </label>
        <label>Other names to search for <span className="muted small">(comma separated)</span>
          <input value={f.keywords} onChange={set('keywords')} placeholder="e.g. Acme Pay, @acmebank" />
        </label>
      </div>
      <div className="form-row">
        <label>Ignore mentions containing <span className="muted small">(comma separated)</span>
          <input value={f.exclude} onChange={set('exclude')} placeholder="e.g. Acme cartoon, Wile E. Coyote" />
        </label>
        <label>Contact to offer in replies
          <input value={f.reply_contact} onChange={set('reply_contact')} maxLength={200} placeholder="e.g. care@acmebank.com" />
        </label>
      </div>
      <fieldset className="rep-sources">
        <legend>Where to look</legend>
        {config.sources.map((s) => (
          <label key={s.key} className={`check ${s.available ? '' : 'muted'}`} title={s.available ? '' : `Needs ${s.needs || 'set-up'} on the server`}>
            <input type="checkbox" checked={f.sources.includes(s.key)} disabled={!s.available} onChange={() => toggle(s.key)} />
            {s.label}{!s.available && <span className="small"> (not set up)</span>}
          </label>
        ))}
      </fieldset>
      <div className="form-row">
        <label>Apple App Store link or id <span className="muted small">(optional)</span>
          <input value={f.apple_app_id} onChange={set('apple_app_id')} placeholder="https://apps.apple.com/in/app/…/id123456789" />
        </label>
        <label>App Store country
          <input value={f.apple_country} onChange={set('apple_country')} maxLength={2} placeholder="in" />
        </label>
      </div>
      <div className="form-row">
        <label>Google place id <span className="muted small">(optional{config.google_reviews ? '' : ', not set up yet'})</span>
          <input value={f.google_place_id} onChange={set('google_place_id')} placeholder="ChIJ…" />
        </label>
        <label>Search phrase to track <span className="muted small">(defaults to the name)</span>
          <input value={f.search_query} onChange={set('search_query')} maxLength={200} placeholder="e.g. Acme Bank reviews" />
        </label>
      </div>
      {entities.length > 0 && (
        <label>Link to a company in your portfolio <span className="muted small">(marks its own website in search results)</span>
          <select value={f.entity_id} onChange={set('entity_id')}>
            <option value="">None</option>
            {entities.map((e) => <option key={e.id} value={e.id}>{e.name} ({e.primary_domain})</option>)}
          </select>
        </label>
      )}
      <div className="actions">
        {onCancel && <button type="button" className="btn ghost" onClick={onCancel}>Cancel</button>}
        <button className="btn" disabled={saving}>{saving ? 'Saving…' : initial ? 'Save changes' : 'Start watching'}</button>
      </div>
    </form>
  )
}

// ------------------------------------------------------------------ list page
function BrandList({ config, user }) {
  const [brands, setBrands] = useState(null)
  const [entities, setEntities] = useState([])
  const [adding, setAdding] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const navigate = useNavigate()
  const load = () => api.listBrands().then(setBrands).catch((e) => setError(e.message))
  useEffect(() => { load(); api.listEntities().then(setEntities).catch(() => {}) }, [])

  async function create(data) {
    setSaving(true); setError(null)
    try {
      const b = await api.createBrand(data)
      navigate(`/reputation/${b.id}`)
    } catch (e) { setError(e.message) } finally { setSaving(false) }
  }

  const canAdd = config.can_manage && brands && brands.length < config.max_brands
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Reputation</h1>
          <p className="muted">Reviews, social posts and news about your brands, scored for sentiment, with alerts when something blows up.</p>
        </div>
        {canAdd && !adding && <button className="btn" onClick={() => setAdding(true)}>Watch a brand</button>}
      </div>
      {error && <div className="banner error">{error}</div>}
      {adding && <div className="card"><h2>Watch a brand</h2><BrandForm config={config} entities={entities} onSave={create} onCancel={() => setAdding(false)} saving={saving} /></div>}
      {brands && brands.length === 0 && !adding && (
        <div className="card">
          <p>No brands yet. {config.can_manage ? 'Add one to start collecting mentions and reviews. The first check covers the last 7 days.' : 'Ask an admin in your organisation to add one.'}</p>
        </div>
      )}
      <div className="rep-brand-grid">
        {(brands ?? []).map((b) => {
          const s = b.summary
          const change = s.score != null && s.previous_score != null ? s.score - s.previous_score : null
          return (
            <Link key={b.id} to={`/reputation/${b.id}`} className="card rep-brand-card">
              <ScoreBadge score={s.score} size="medium" />
              <div className="rep-brand-main">
                <div className="strong">{b.name}</div>
                <div className="muted small">
                  {s.total} mentions in 30 days
                  {change != null && change !== 0 && <span className={change > 0 ? 'ok' : 'error'}> · {change > 0 ? '+' : ''}{change} vs previous 30</span>}
                </div>
                <div className="rep-mini-bar" aria-hidden="true">
                  {['positive', 'neutral', 'negative'].map((k) => s.total > 0 && <span key={k} className={`rep-bar-${k}`} style={{ flexGrow: s[k] }} />)}
                </div>
                {s.open > 0 && <div className="small rep-open">{s.open} negative to review</div>}
              </div>
            </Link>
          )
        })}
      </div>
      <p className="muted small rep-footnote">
        Sentiment is scored automatically and can be wrong, especially for sarcasm and languages other than English. You can correct any label.
        {user.role === 'owner' && ' Data sources and their licence terms are listed in docs/REPUTATION.md.'}
      </p>
    </>
  )
}

// ------------------------------------------------------------------ mentions inbox
function MentionRow({ m, onChange, aiReplies }) {
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState(m.reply_text || '')
  const [busy, setBusy] = useState(false)
  const [by, setBy] = useState(null)
  const [error, setError] = useState(null)

  async function patch(data) {
    setError(null)
    try { onChange(await api.updateMention(m.id, data)) } catch (e) { setError(e.message) }
  }
  async function suggest() {
    setBusy(true); setError(null)
    try { const r = await api.suggestReply(m.id); setDraft(r.text); setBy(r.by) } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  async function copy() {
    try { await navigator.clipboard.writeText(draft) } catch { /* clipboard blocked: the text is still selectable */ }
  }

  return (
    <div className={`rep-mention rep-mention-${m.label} ${m.status !== 'new' ? 'rep-done' : ''}`}>
      <div className="rep-mention-head">
        <SentimentPill label={m.label} />
        <span className="chip">{SOURCE_LABELS[m.source] || m.source}</span>
        <Stars n={m.rating} />
        {m.author && <span className="muted small">{m.author}</span>}
        <span className="muted small rep-when">{when(m.published_at)}</span>
      </div>
      {m.title && <div className="strong rep-title">{m.url ? <a href={m.url} target="_blank" rel="noopener noreferrer nofollow">{m.title}</a> : m.title}</div>}
      {m.text && <p className="rep-text">{m.text.length > 420 && !open ? m.text.slice(0, 420) + '…' : m.text}</p>}
      {!m.title && m.url && <a className="small" href={m.url} target="_blank" rel="noopener noreferrer nofollow">Open original</a>}
      <div className="rep-mention-actions">
        <select value={m.status} onChange={(e) => patch({ status: e.target.value })} aria-label="Status">
          {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select value={m.label} onChange={(e) => patch({ label: e.target.value })} aria-label="Correct the sentiment">
          <option value="positive">Positive</option><option value="neutral">Neutral</option><option value="negative">Negative</option>
        </select>
        {m.kind !== 'news' && <button className="btn ghost small-btn" onClick={() => setOpen(!open)}>{open ? 'Close' : 'Reply'}</button>}
      </div>
      {open && (
        <div className="rep-reply">
          <textarea rows={4} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Write a reply, or get a suggestion" maxLength={4000} />
          <div className="actions">
            <button className="btn ghost small-btn" onClick={suggest} disabled={busy}>{busy ? 'Writing…' : aiReplies ? 'Suggest with AI' : 'Suggest a reply'}</button>
            <button className="btn ghost small-btn" onClick={copy} disabled={!draft}>Copy</button>
            <button className="btn small-btn" onClick={() => patch({ reply_text: draft, status: 'replied' })} disabled={!draft}>Mark as replied</button>
          </div>
          <p className="muted small">
            {by === 'ai' ? 'Drafted by AI. Check it before posting. ' : ''}
            Post the reply yourself on {SOURCE_LABELS[m.source] || 'the site'}; ProjectScore does not post anything for you.
          </p>
        </div>
      )}
      {error && <div className="banner error">{error}</div>}
    </div>
  )
}

function Inbox({ brand, config }) {
  const [filters, setFilters] = useState({ label: 'negative', source: '', status: 'new', q: '', days: 30 })
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(0)
  const limit = 25
  const load = useCallback(() => {
    api.listMentions(brand.id, { ...filters, limit, offset: page * limit }).then(setData).catch((e) => setError(e.message))
  }, [brand.id, filters, page])
  useEffect(() => { load() }, [load])
  const set = (k) => (e) => { setPage(0); setFilters({ ...filters, [k]: e.target.value }) }
  const replace = (m) => setData({ ...data, mentions: data.mentions.map((x) => (x.id === m.id ? m : x)) })

  return (
    <div className="card table-card">
      <div className="table-tools">
        <input className="search" type="search" placeholder="Search text" value={filters.q} onChange={set('q')} maxLength={100} />
        <div className="rep-filters">
          <select value={filters.label} onChange={set('label')} aria-label="Sentiment">
            <option value="">All sentiment</option><option value="negative">Negative</option><option value="neutral">Neutral</option><option value="positive">Positive</option>
          </select>
          <select value={filters.status} onChange={set('status')} aria-label="Status">
            <option value="">Any status</option>{Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select value={filters.source} onChange={set('source')} aria-label="Source">
            <option value="">All sources</option>{Object.entries(SOURCE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select value={filters.days} onChange={set('days')} aria-label="Period">
            <option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>1 year</option>
          </select>
        </div>
      </div>
      {error && <div className="banner error">{error}</div>}
      <div className="rep-mentions">
        {data && data.mentions.length === 0 && <p className="muted pad">Nothing matches these filters.</p>}
        {(data?.mentions ?? []).map((m) => <MentionRow key={m.id} m={m} onChange={replace} aiReplies={config.ai_replies} />)}
      </div>
      {data && data.total > limit && (
        <div className="table-tools">
          <span className="muted small">{page * limit + 1} to {Math.min(data.total, (page + 1) * limit)} of {data.total}</span>
          <div className="actions">
            <button className="btn ghost small-btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
            <button className="btn ghost small-btn" disabled={(page + 1) * limit >= data.total} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ Google reviews (live)
function GoogleReviews({ brand }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { api.googleReviews(brand.id).then(setData).catch((e) => setError(e.message)) }, [brand.id])
  if (error) return <div className="banner error">{error}</div>
  if (!data) return <p className="muted">Loading from Google…</p>
  return (
    <div className="card">
      <div className="section-head">
        <h2>{data.name || brand.name} on Google</h2>
        <div className="strong">{data.rating ?? '–'} ★ <span className="muted small">from {data.count ?? 0} reviews</span></div>
      </div>
      <p className="muted small">Google shows up to 5 recent reviews and does not allow them to be stored, so these are fetched live each time. {data.maps_url && <a href={data.maps_url} target="_blank" rel="noopener noreferrer">Open in Google Maps</a>}</p>
      {data.reviews.map((r, i) => (
        <div key={i} className={`rep-mention rep-mention-${r.label}`}>
          <div className="rep-mention-head"><SentimentPill label={r.label} /><Stars n={r.rating} /><span className="muted small">{r.author}</span><span className="muted small rep-when">{r.when}</span></div>
          {r.text && <p className="rep-text">{r.text}</p>}
        </div>
      ))}
      <p className="muted small">Reviews from Google.</p>
    </div>
  )
}

// ------------------------------------------------------------------ search results
function SearchTracking({ brand }) {
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  useEffect(() => { api.searchResults(brand.id).then(setData).catch((e) => setError(e.message)) }, [brand.id])
  async function refresh() {
    setBusy(true); setError(null)
    try { setData(await api.takeSearch(brand.id)) } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  if (!data) return error ? <div className="banner error">{error}</div> : null
  if (!data.available) {
    return <div className="card"><p>Search tracking is not set up on this server yet. It needs a Brave Search API key (BRAVE_SEARCH_API_KEY).</p></div>
  }
  const latest = data.latest
  return (
    <>
      {error && <div className="banner error">{error}</div>}
      <div className="card table-card">
        <div className="section-head">
          <div>
            <h2>What people see when they search{latest ? ` "${latest.query}"` : ''}</h2>
            {latest && <p className="muted small">Checked {when(latest.taken_at)}. {latest.negative_top10} negative and {latest.owned_top10} of your own pages in the top 10. Checked again every week.</p>}
          </div>
          <button className="btn ghost" onClick={refresh} disabled={busy}>{busy ? 'Checking…' : 'Check now'}</button>
        </div>
        {!latest && <p className="muted pad">No results yet. Press Check now.</p>}
        {latest && (
          <div className="table-scroll">
            <table>
              <thead><tr><th>#</th><th>Result</th><th>Tone</th><th>Change</th></tr></thead>
              <tbody>
                {latest.results.map((r) => (
                  <tr key={r.url} className="static">
                    <td className="num">{r.rank}</td>
                    <td>
                      <a href={r.url} target="_blank" rel="noopener noreferrer nofollow">{r.title || r.url}</a>
                      <div className="muted small">{r.domain}{r.owned && <span className="chip rep-owned">your site</span>}</div>
                      {r.snippet && <div className="small">{r.snippet}</div>}
                    </td>
                    <td><SentimentPill label={r.label} /></td>
                    <td className="small">{r.new ? <span className="rep-new">New</span> : r.previous_rank && r.previous_rank !== r.rank ? (r.previous_rank > r.rank ? `▲ ${r.previous_rank - r.rank}` : `▼ ${r.rank - r.previous_rank}`) : '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data.history.length > 1 && (
          <p className="muted small pad">Negative results in the top 10 over time: {data.history.map((h) => h.negative_top10).join(' → ')}</p>
        )}
        <p className="muted small pad">Search results by Brave Search. Tone is judged from the title and snippet only.</p>
      </div>
    </>
  )
}

// ------------------------------------------------------------------ import / add
function AddData({ brand, onDone }) {
  const [csv, setCsv] = useState('')
  const [one, setOne] = useState({ text: '', rating: '', author: '', url: '' })
  const [msg, setMsg] = useState(null)
  const [error, setError] = useState(null)
  async function doImport(e) {
    e.preventDefault(); setError(null); setMsg(null)
    try { const r = await api.importMentions(brand.id, csv); setMsg(`Imported ${r.imported}. ${r.duplicates} already there, ${r.skipped} empty rows skipped.`); setCsv(''); onDone() } catch (err) { setError(err.message) }
  }
  async function addOne(e) {
    e.preventDefault(); setError(null); setMsg(null)
    try {
      await api.addMention(brand.id, { text: one.text, rating: one.rating ? Number(one.rating) : null, author: one.author || null, url: one.url || null })
      setOne({ text: '', rating: '', author: '', url: '' }); setMsg('Added.'); onDone()
    } catch (err) { setError(err.message) }
  }
  async function readFile(e) {
    const file = e.target.files?.[0]
    if (file) setCsv(await file.text())
  }
  return (
    <div className="rep-two">
      <div className="card">
        <h2>Import reviews from a file</h2>
        <p className="muted small">For sites we can't read directly, such as Google Business Profile exports, Trustpilot, Glassdoor or your support desk. Use a CSV with a header row. Only <span className="mono">text</span> is required; <span className="mono">date, source, author, rating, title, url</span> are optional.</p>
        <form className="form" onSubmit={doImport}>
          <input type="file" accept=".csv,text/csv" onChange={readFile} />
          <textarea rows={5} value={csv} onChange={(e) => setCsv(e.target.value)} placeholder={'date,source,author,rating,text\n2026-11-10,Trustpilot,Ann,1,"Waited 3 weeks for a refund"'} />
          <div className="actions"><button className="btn" disabled={!csv.trim()}>Import</button></div>
        </form>
      </div>
      <div className="card">
        <h2>Add one by hand</h2>
        <form className="form" onSubmit={addOne}>
          <textarea required minLength={2} rows={4} value={one.text} onChange={(e) => setOne({ ...one, text: e.target.value })} placeholder="Paste the review or post" />
          <div className="form-row">
            <select value={one.rating} onChange={(e) => setOne({ ...one, rating: e.target.value })} aria-label="Stars"><option value="">No rating</option>{[5, 4, 3, 2, 1].map((n) => <option key={n} value={n}>{n} stars</option>)}</select>
            <input value={one.author} onChange={(e) => setOne({ ...one, author: e.target.value })} placeholder="Author (optional)" />
          </div>
          <input value={one.url} onChange={(e) => setOne({ ...one, url: e.target.value })} placeholder="Link (optional)" pattern="https?://.*" />
          <div className="actions"><button className="btn">Add</button></div>
        </form>
      </div>
      {msg && <div className="banner">{msg}</div>}
      {error && <div className="banner error">{error}</div>}
    </div>
  )
}

// ------------------------------------------------------------------ brand dashboard
function BrandView({ config, id }) {
  const [brand, setBrand] = useState(null)
  const [tab, setTab] = useState('overview')
  const [days, setDays] = useState(30)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [entities, setEntities] = useState([])
  const [saving, setSaving] = useState(false)
  const navigate = useNavigate()
  const load = useCallback(() => api.getBrand(id, days).then(setBrand).catch((e) => setError(e.message)), [id, days])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!brand?.polling) return
    const t = setTimeout(load, 5000)
    return () => clearTimeout(t)
  }, [brand, load])
  useEffect(() => { if (config.can_manage) api.listEntities().then(setEntities).catch(() => {}) }, [config.can_manage])

  async function poll() {
    setError(null)
    try { await api.pollBrand(id); setNotice('Checking all sources now. This takes up to a minute.'); load() } catch (e) { setError(e.message) }
  }
  async function save(data) {
    setSaving(true); setError(null)
    try { setBrand({ ...(await api.updateBrand(id, data)) }); setNotice('Saved.'); setTab('overview'); load() } catch (e) { setError(e.message) } finally { setSaving(false) }
  }
  async function remove() {
    if (!window.confirm(`Stop watching ${brand.name} and delete all its collected mentions?`)) return
    try { await api.deleteBrand(id); navigate('/reputation') } catch (e) { setError(e.message) }
  }

  const tabs = useMemo(() => [
    ['overview', 'Overview'], ['inbox', 'Mentions'],
    ...(config.google_reviews && brand?.google_place_id ? [['google', 'Google reviews']] : []),
    ['search', 'Search results'], ['add', 'Import'], ...(config.can_manage ? [['settings', 'Settings']] : []),
  ], [config, brand])

  if (!brand) return error ? <div className="banner error">{error}</div> : null
  const s = brand.summary
  const failing = Object.entries(brand.source_status).filter(([, v]) => !v.ok)
  return (
    <>
      <Link to="/reputation" className="back">← All brands</Link>
      <div className="page-head">
        <div className="rep-head">
          <ScoreBadge score={s.score} />
          <div>
            <h1>{brand.name}</h1>
            <p className="muted small">
              {brand.polling ? 'Checking sources now…' : `Last checked ${when(brand.last_polled_at)}. Checked automatically every few hours.`}
            </p>
          </div>
        </div>
        <div className="actions">
          <a className="btn ghost" href={`/api/reputation/brands/${brand.id}/export.csv`}>Export CSV</a>
          <button className="btn" onClick={poll} disabled={brand.polling}>Check now</button>
        </div>
      </div>
      {notice && <div className="banner">{notice}</div>}
      {error && <div className="banner error">{error}</div>}
      {failing.length > 0 && (
        <div className="banner">Some sources could not be read last time: {failing.map(([k, v]) => `${SOURCE_LABELS[k] || k} (${v.error || 'error'})`).join('; ')}. The rest worked.</div>
      )}
      <div className="tabs" role="tablist">
        {tabs.map(([k, label]) => <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? 'active' : ''}`} onClick={() => setTab(k)}>{label}</button>)}
      </div>

      {tab === 'overview' && (
        <>
          <div className="tiles">
            <div className="tile"><div className="tile-label">Mentions ({s.days} days)</div><div className="tile-value">{s.total}</div></div>
            <div className="tile"><div className="tile-label">Negative</div><div className={`tile-value ${s.negative ? 'warn' : ''}`}>{s.negative}</div></div>
            <div className="tile"><div className="tile-label">Negative to review</div><div className={`tile-value ${s.open ? 'warn' : ''}`}>{s.open}</div></div>
            <div className="tile"><div className="tile-label">Average rating</div><div className="tile-value">{s.average_rating ?? '–'}{s.average_rating && <span className="small muted"> ★ ({s.reviews})</span>}</div></div>
          </div>
          <div className="card">
            <div className="section-head">
              <h2>Mentions per day</h2>
              <div className="rep-legend small">
                <span><i className="rep-bar-positive" /> Positive {s.positive}</span>
                <span><i className="rep-bar-neutral" /> Neutral {s.neutral}</span>
                <span><i className="rep-bar-negative" /> Negative {s.negative}</span>
                <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Period">
                  <option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option>
                </select>
              </div>
            </div>
            <Trend daily={s.daily} />
            {s.score == null && <p className="muted small">The reputation score appears once there are at least 5 mentions in the period.</p>}
            {s.score != null && <p className="muted small">Score {s.score} of 100{s.previous_score != null ? `, ${s.previous_score} in the previous ${s.days} days` : ''}. 60% comes from the balance of positive and negative mentions and 40% from star ratings, when there are any.</p>}
          </div>
          <div className="card table-card">
            <h2>By source</h2>
            <div className="table-scroll">
              <table>
                <thead><tr><th>Source</th><th className="num">Total</th><th className="num">Positive</th><th className="num">Neutral</th><th className="num">Negative</th><th>Last check</th></tr></thead>
                <tbody>
                  {Array.from(new Set([...s.by_source.map((x) => x.source), ...brand.sources])).map((src) => {
                    const row = s.by_source.find((x) => x.source === src) || { total: 0, positive: 0, neutral: 0, negative: 0 }
                    const st = brand.source_status[src]
                    return (
                      <tr key={src} className="static">
                        <td>{SOURCE_LABELS[src] || src}</td>
                        <td className="num">{row.total}</td><td className="num">{row.positive}</td><td className="num">{row.neutral}</td><td className="num">{row.negative}</td>
                        <td className="small">{st ? (st.ok ? `${when(st.at)}, ${st.count} new` : <span className="error">Failed {when(st.at)}</span>) : ['import', 'manual'].includes(src) ? '–' : 'Not yet'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
      {tab === 'inbox' && <Inbox brand={brand} config={config} />}
      {tab === 'google' && <GoogleReviews brand={brand} />}
      {tab === 'search' && <SearchTracking brand={brand} />}
      {tab === 'add' && <AddData brand={brand} onDone={load} />}
      {tab === 'settings' && (
        <div className="card">
          <h2>Settings</h2>
          <BrandForm config={config} initial={brand} entities={entities} onSave={save} saving={saving} />
          <div className="divider" />
          <button className="btn ghost danger" onClick={remove}>Stop watching and delete data</button>
        </div>
      )}
    </>
  )
}

export default function Reputation() {
  const { user } = useOutletContext()
  const { brandId } = useParams()
  const [config, setConfig] = useState(null)
  useEffect(() => { api.reputationConfig().then(setConfig).catch(() => setConfig({ enabled: false })) }, [])
  if (!config) return null
  if (!config.enabled) return <div className="card"><p>The reputation module is not switched on for this server.</p></div>
  return brandId ? <BrandView key={brandId} config={config} id={brandId} /> : <BrandList config={config} user={user} />
}
