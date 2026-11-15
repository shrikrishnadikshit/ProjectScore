import { useState } from 'react'
import { api } from '../api.js'

const SAMPLE = 'name,domain,tier,industry\nAcme Supplies,acme.com,1,\nBeta Logistics,beta-logistics.in,2,\n'

export default function ImportForm({ onDone, onCancel }) {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function readFile(file) {
    if (!file) return
    if (file.size > 1_000_000) { setError('The file is larger than 1 MB.'); return }
    setText(await file.text())
  }
  async function submit(e) {
    e.preventDefault(); setBusy(true); setError(null)
    try { setResult(await api.importEntities(text)); onDone?.() } catch (err) { setError(err.message) }
    setBusy(false)
  }
  const sampleHref = 'data:text/csv;charset=utf-8,' + encodeURIComponent(SAMPLE)

  return (
    <section className="card">
      <h2>Import companies from a spreadsheet</h2>
      {result ? (
        <>
          <p><b>{result.added.length}</b> added{result.scans_queued ? `, and their first scans have started (one at a time, so a long list takes a while)` : ''}.</p>
          {result.skipped.length > 0 && (
            <>
              <p className="small strong">{result.skipped.length} skipped:</p>
              <ul className="small">{result.skipped.slice(0, 50).map((s) => <li key={s.row}>Row {s.row} ({s.value || 'empty'}): {s.reason}</li>)}</ul>
            </>
          )}
          <div className="actions"><button className="btn primary" onClick={onCancel}>Done</button></div>
        </>
      ) : (
        <form className="form" style={{ maxWidth: 'none' }} onSubmit={submit}>
          <p className="muted small">Save your spreadsheet as CSV with the columns <b>name</b> and <b>domain</b>, and optionally <b>tier</b> (1 to 3) and <b>industry</b>. Up to 500 companies at a time. <a href={sampleHref} download="projectscore-import-example.csv">Download an example</a>.</p>
          <label>CSV file<input type="file" accept=".csv,text/csv" onChange={(e) => readFile(e.target.files[0])} /></label>
          <label>Or paste the rows<textarea rows={5} className="mono small" value={text} onChange={(e) => setText(e.target.value)} placeholder={SAMPLE} /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions">
            <button type="button" className="btn ghost" onClick={onCancel}>Cancel</button>
            <button className="btn primary" disabled={!text.trim() || busy}>{busy ? 'Importing…' : 'Import and rate'}</button>
          </div>
        </form>
      )}
    </section>
  )
}
