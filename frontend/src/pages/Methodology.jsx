import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import PublicFooter from '../components/PublicFooter.jsx'

const FACTORS = [
  ['Compromise signals', '20%', 'Botnet, malware and attack activity from the organisation\'s addresses (abuse.ch, Spamhaus DROP, blocklist.de).'],
  ['Vulnerabilities', '18%', 'Outdated or vulnerable internet-facing software, weighted by CVSS and CISA\'s list of actively exploited flaws.'],
  ['Network exposure', '12%', 'Risky services open to the internet, such as remote desktop, databases and file sharing.'],
  ['Email security', '8%', 'SPF, DMARC, DKIM and MTA-STS, which stop others sending email as the organisation.'],
  ['Encryption (TLS)', '8%', 'Certificates, protocol versions and HSTS.'],
  ['Web application security', '8%', 'Security headers, cookie flags, vulnerable JavaScript libraries, security.txt and privacy notice.'],
  ['DNS health', '6%', 'DNSSEC and dangling records that allow subdomain takeover.'],
  ['Breach history', '6%', 'Publicly reported data breaches, fading over time.'],
  ['Brand and impersonation', '4%', 'Look-alike domains that can be used for phishing.'],
]
const SOURCES = [
  ['Public DNS, certificate transparency (crt.sh, Cert Spotter), and one standard web request per host', 'Collected directly'],
  ['Shodan InternetDB (open ports and known CVEs)', 'Free tier; commercial licence required before paid use'],
  ['NVD (CVSS) and FIRST EPSS (exploit likelihood)', 'Public, free'],
  ['CISA Known Exploited Vulnerabilities catalogue', 'Public, free'],
  ['abuse.ch Feodo Tracker and URLhaus, Spamhaus DROP, blocklist.de', 'Free threat-intelligence feeds'],
  ['Have I Been Pwned breach list', 'CC BY 4.0'],
  ['RDAP registries and Team Cymru IP-to-ASN (network owner and hosting country)', 'Public'],
]
const PRINCIPLES = [
  ['Transparency', 'This page, the factor weights and every finding\'s evidence are visible to customers and to the rated organisation.'],
  ['Disputes and correction', 'Any finding can be disputed by a customer or by the rated organisation; wrong findings are removed and the score recalculated.'],
  ['Accuracy and validation', 'Each finding carries a confidence level; checks skip factors when data is unreliable rather than guessing, and results are checked against real incidents over time.'],
  ['Model governance', 'Scores carry a model version; method changes are documented and applied to everyone at once.'],
  ['Independence', 'Ratings cannot be bought or improved by becoming a customer. They change only when what is visible from the internet changes.'],
  ['Confidentiality', 'Results of in-depth scans, code reviews, questionnaires and certificates stay private to the customer that ran them.'],
]

const STATUS = { applied: 'Followed', mapped: 'Findings tagged', referenced: 'Referenced only' }

export default function Methodology() {
  const [std, setStd] = useState(null)
  useEffect(() => { fetch('/api/standards').then((r) => r.ok ? r.json() : null).then(setStd).catch(() => {}) }, [])
  return (
    <div className="public">
      <Link to="/" className="brand">ProjectScore</Link>
      <h1>How ProjectScore ratings work</h1>
      <p>ProjectScore rates the external security of an organisation on a scale from 250 to 900 (A to F), using only what anyone can see from the internet. We do not log in, exploit anything or send attack traffic; in-depth testing is only ever done for an organisation that has proved it owns the domain and given written permission.</p>

      <section className="card">
        <h2>What we look at</h2>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Factor</th><th className="num">Weight</th><th>What it covers</th></tr></thead>
            <tbody>{FACTORS.map(([f, w, d]) => <tr key={f} className="static"><td className="strong">{f}</td><td className="num">{w}</td><td className="small">{d}</td></tr>)}</tbody>
          </table>
        </div>
        <p className="small muted">Identity security (10%) is reserved for a future factor; until then the other weights are scaled up proportionally.</p>
      </section>

      <section className="card">
        <h2>How a score is calculated</h2>
        <ul className="small">
          <li>Each finding counts by severity (critical 10, high 7, medium 4, low 1) × how sure we are × how recent it is. Most findings fade with a 30-day half-life once fixed or no longer seen; compromise signals take 60 days and breaches a year.</li>
          <li>Penalties are scaled by the size of the organisation (square root of the number of systems), so large organisations are not punished for being large.</li>
          <li>Each factor becomes a 0 to 100 score, the weighted average becomes the overall rating, and grades are A from 800, B from 700, C from 600, D from 500 and F below.</li>
          <li>Two hard limits: active compromise caps the rating at 640, and an actively exploited critical vulnerability caps it at 700.</li>
          <li>Factors we could not assess are left out rather than counted as perfect, and the rating shows its coverage.</li>
        </ul>
      </section>

      <section className="card">
        <h2>Testing standards we follow</h2>
        <p className="small muted">How our testing lines up with recognised global methodologies. Every finding shows its CWE, OWASP Top 10 and OWASP testing guide (WSTG) IDs alongside MITRE ATT&CK, and an evidence record with its source, collection time and a SHA-256 fingerprint.</p>
        {std ? std.catalogue.map((a) => (
          <div key={a.area} style={{ marginTop: 12 }}>
            <h3>{a.area}</h3>
            <table>
              <tbody>{a.standards.map((s) => <tr key={s.name} className="static"><td className="strong small" style={{ width: '32%' }}>{s.name}</td><td className="small" style={{ width: '16%' }}>{STATUS[s.status]}</td><td className="small muted">{s.how}</td></tr>)}</tbody>
            </table>
          </div>
        )) : <p className="muted small">Loading…</p>}
      </section>

      <section className="card">
        <h2>Data sources</h2>
        <ul className="small">{SOURCES.map(([s, l]) => <li key={s}>{s} <span className="muted">({l})</span></li>)}</ul>
      </section>

      <section className="card">
        <h2>Fair and accurate ratings</h2>
        <p className="small">ProjectScore follows the principles for fair and accurate security ratings published by the US Chamber of Commerce and leading ratings providers:</p>
        <ul className="small">{PRINCIPLES.map(([p, d]) => <li key={p}><b>{p}.</b> {d}</li>)}</ul>
      </section>

      <section className="card">
        <h2>If you are a rated organisation</h2>
        <p className="small">You can see why you were rated, dispute any finding, or ask us to stop scanning your domain on the <Link to="/scanner">scanner information page</Link>. You can also get a free one-time rating of your own domain on the <Link to="/free-report">free report page</Link>.</p>
      </section>
      <PublicFooter />
    </div>
  )
}
