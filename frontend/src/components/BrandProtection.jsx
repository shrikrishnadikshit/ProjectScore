import { useEffect, useState } from 'react'
import { api } from '../api.js'

const LEVEL = { low: ['Nothing serious found', 'low'], medium: ['Needs review', 'medium'], high: ['Action needed', 'high'] }

function Report({ items }) {
  return <span className="small"> Report: {items.map(([label, url], i) => <span key={url}>{i > 0 && ' · '}<a href={url} target="_blank" rel="noreferrer">{label}</a></span>)}</span>
}

export default function BrandProtection({ entityId, version }) {
  const [d, setD] = useState(null)
  const [allSites, setAllSites] = useState(false)
  useEffect(() => { api.brand(entityId).then(setD).catch(() => setD(null)) }, [entityId, version])
  if (!d) return null
  const [label, sev] = LEVEL[d.level]
  const web = d.report.website.filter(([, u]) => u !== 'rdap')
  const sites = allSites ? d.fake_sites : d.fake_sites.filter((s) => s.kind || s.mail).slice(0, 10)
  return (
    <section className="card">
      <div className="section-head">
        <div>
          <h2>Brand protection</h2>
          <p className="muted small">Who may be pretending to be this company: fake websites on look-alike domains, apps using its name, and news of attacks on it. Each item links to where it can be reported for takedown.</p>
        </div>
        <span className={`sev sev-${sev}`}>{label}</span>
      </div>

      <h3>Fake and look-alike websites</h3>
      {d.fake_sites.length === 0 ? <p className="muted small">No look-alike domains with a website or email found.</p> : (
        <>
          <ul className="small">
            {sites.map((s) => (
              <li key={s.id} style={{ marginBottom: 4 }}>
                <span className={`sev sev-${s.severity}`}>{s.severity}</span> <span className="mono">{s.domain}</span>{s.detail ? `: ${s.detail}` : s.mail ? ': can send email' : ': registered, hosts a website'}
                {(s.kind === 'phishing_like' || s.kind === 'copies_site') && <><Report items={web} /> · <a className="small" href={`https://lookup.icann.org/en/lookup?name=${encodeURIComponent(s.domain)}`} target="_blank" rel="noreferrer">registrar abuse contact</a></>}
              </li>
            ))}
          </ul>
          {d.fake_sites.length > sites.length && !allSites && <button className="link-btn small" onClick={() => setAllSites(true)}>Show all {d.fake_sites.length} look-alike domains</button>}
        </>
      )}

      <h3>Apps using the company's name</h3>
      {!d.checked_at ? <p className="muted small">Checked after the next scan.</p> : d.apps.length === 0 ? <p className="muted small">No apps using the name in the Apple App Store.</p> : (
        <>
          <p className="small">{d.unofficial_apps} of {d.apps.length} App Store apps using the name are published by someone else. Many are legitimate add-ons; check any that look official.<Report items={d.report.app_store} /></p>
          <ul className="small">
            {d.apps.slice(0, 10).map((a) => <li key={a.url || a.name}>{a.url ? <a href={a.url} target="_blank" rel="noreferrer">{a.name}</a> : a.name} <span className="muted">by {a.publisher || 'unknown'}</span>{a.official ? <span className="sev sev-info" style={{ marginLeft: 6 }}>official</span> : <span className="sev sev-medium" style={{ marginLeft: 6 }}>other publisher</span>}</li>)}
          </ul>
          <p className="muted small">Google Play has no public search we can use; report fake Android apps through <a href={d.report.google[0][1]} target="_blank" rel="noreferrer">{d.report.google[0][0]}</a>.</p>
        </>
      )}

      <h3>Official social media profiles</h3>
      {d.social.length === 0 ? <p className="muted small">{d.checked_at ? 'No social profiles linked from the company website.' : 'Checked after the next scan.'}</p> : (
        <ul className="small">
          {d.social.map((p) => <li key={p.url}><b>{p.platform}</b>: <a href={p.url} target="_blank" rel="noreferrer">{p.url.replace(/^https?:\/\/(www\.)?/, '')}</a>{d.report[p.platform] && <Report items={d.report[p.platform]} />}</li>)}
        </ul>
      )}
      <p className="muted small">These are the profiles the company links from its own website. Any other account using its name and logo is likely fake. Social networks do not allow automated searching, so report fakes you see with the links above.</p>

      <h3>Attacks in the news (last 6 months)</h3>
      {!d.checked_at ? <p className="muted small">Checked after the next scan.</p> : d.news.length === 0 ? <p className="muted small">No news articles about breaches or cyber attacks naming this company.</p> : (
        <ul className="small">
          {d.news.slice(0, 10).map((n) => <li key={n.url}>{n.date} · <a href={n.url} target="_blank" rel="noreferrer">{n.title}</a> <span className="muted">({n.source})</span></li>)}
          <li className="muted">Headlines are matched on the company name, so check that each one is really about this company.</li>
        </ul>
      )}
      <p className="muted small">Sources: {d.sources.join(', ')}, and our own look-alike domain checks.</p>
    </section>
  )
}
