import { useEffect, useMemo, useState } from 'react'

const METHOD_CLASS = { get: 'ok', post: 'warn', put: 'warn', patch: 'warn', delete: 'error' }
const VERIFY = `import hashlib, hmac, time

def is_from_projectscore(secret: str, raw_body: bytes, header: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    ts = int(parts["t"])
    if abs(time.time() - ts) > 300:   # older than 5 minutes: reject
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))`
const EXAMPLE = `{
  "id": "6f1c…",
  "type": "alert.score_drop",
  "created_at": "2026-11-18T09:00:00+00:00",
  "data": { "alert_id": 42, "entity_id": 7, "severity": "warning",
            "title": "Example Ltd dropped 34 points", "detail": "…" }
}`

function group(path) {
  const p = path.replace(/^\/api\//, '').split('/')
  return p[0] === 'public' ? 'public' : p[0]
}

export default function ApiDocs() {
  const [spec, setSpec] = useState(null)
  const [q, setQ] = useState('')
  const [error, setError] = useState(null)
  useEffect(() => { fetch('/openapi.json').then((r) => r.json()).then(setSpec).catch((e) => setError(e.message)) }, [])
  const groups = useMemo(() => {
    if (!spec) return []
    const out = {}
    for (const [path, ops] of Object.entries(spec.paths)) {
      if (!path.startsWith('/api/')) continue
      for (const [m, op] of Object.entries(ops)) {
        const hay = `${m} ${path} ${op.summary || ''} ${op.description || ''}`.toLowerCase()
        if (q && !hay.includes(q.toLowerCase())) continue
        ;(out[group(path)] ||= []).push({ m, path, op })
      }
    }
    return Object.entries(out).sort(([a], [b]) => a.localeCompare(b))
  }, [spec, q])
  const origin = window.location.origin

  return (
    <>
      <div className="page-head">
        <div>
          <h1>API docs</h1>
          <p className="muted">Everything the app does goes through this API. Create a read-only key in Settings, then send it as <span className="mono">Authorization: Bearer ps_…</span>. Keys can call any GET endpoint for your organisation.</p>
        </div>
        <div className="row-actions"><a className="btn ghost" href="/openapi.json" download>Download OpenAPI spec</a></div>
      </div>

      <section className="card">
        <h2>Quick start</h2>
        <pre className="mono small code-block">{`curl -H "Authorization: Bearer ps_…" ${origin}/api/entities
curl -H "Authorization: Bearer ps_…" ${origin}/api/entities/7
curl -H "Authorization: Bearer ps_…" -o portfolio.xlsx ${origin}/api/exports/portfolio.xlsx`}</pre>
      </section>

      <section className="card">
        <h2>Webhooks</h2>
        <p className="small">Set an HTTPS address in Settings → Integrations. Every new alert is POSTed to it as JSON:</p>
        <pre className="mono small code-block">{EXAMPLE}</pre>
        <p className="small">Each request has an <span className="mono">X-ProjectScore-Signature: t=&lt;time&gt;,v1=&lt;signature&gt;</span> header. The signature is the HMAC-SHA256 of the time, a dot and the raw body, keyed with your signing secret. Check it before trusting the event:</p>
        <pre className="mono small code-block">{VERIFY}</pre>
        <p className="muted small">We do not follow redirects and only call public internet addresses. Reply with any 2xx status within 10 seconds.</p>
      </section>

      <section className="card table-card">
        <div className="section-head">
          <h2>Endpoints</h2>
          <input className="search" placeholder="Search endpoints" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 260 }} />
        </div>
        {error && <p className="error pad">{error}</p>}
        {!spec ? <p className="muted pad">Loading…</p> : groups.map(([g, ops]) => (
          <div key={g} className="pad">
            <h3 style={{ textTransform: 'capitalize' }}>{g.replace(/-/g, ' ')}</h3>
            {ops.map(({ m, path, op }) => (
              <details key={m + path} className="small" style={{ padding: '4px 0' }}>
                <summary><span className={`mono ${METHOD_CLASS[m] || ''}`} style={{ display: 'inline-block', width: 60 }}>{m.toUpperCase()}</span> <span className="mono">{path}</span> <span className="muted">{op.summary}</span></summary>
                <div style={{ padding: '6px 0 8px 64px' }}>
                  {op.description && <p style={{ whiteSpace: 'pre-wrap' }}>{op.description}</p>}
                  {(op.parameters || []).length > 0 && <p><span className="muted">Parameters:</span> {op.parameters.map((p) => `${p.name} (${p.in}${p.required ? ', required' : ''})`).join(', ')}</p>}
                  {op.requestBody && <p><span className="muted">Body:</span> <span className="mono">{(op.requestBody.content?.['application/json']?.schema?.$ref || 'JSON').split('/').pop()}</span></p>}
                  {m !== 'get' && !path.startsWith('/api/public') && <p className="muted">Needs a signed-in session (API keys are read-only).</p>}
                </div>
              </details>
            ))}
          </div>
        ))}
      </section>
    </>
  )
}
