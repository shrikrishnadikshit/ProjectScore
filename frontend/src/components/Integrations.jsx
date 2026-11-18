import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Integrations({ isAdmin }) {
  const [data, setData] = useState(null)
  const [slack, setSlack] = useState('')
  const [jira, setJira] = useState({ site: '', email: '', project: '', issue_type: 'Task', api_token: '' })
  const [msg, setMsg] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.listIntegrations().then((d) => {
    setData(d)
    if (d.jira.config) setJira({ ...d.jira.config, api_token: '' })
  }).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])
  if (!data) return error ? <div className="card error">{error}</div> : null

  const run = (fn, ok) => async (e) => {
    e?.preventDefault(); setError(null); setMsg(null)
    try { await fn(); setMsg(ok); load() } catch (err) { setError(err.message) }
  }
  const status = (row) => row.connected
    ? <span className={row.last_error ? 'error' : 'ok'}>{row.last_error ? `Connected, last attempt failed (${row.last_error})` : 'Connected'}</span>
    : <span className="muted">Not connected</span>

  return (
    <section className="card">
      <h2>Integrations</h2>
      <p className="muted small">Send alerts to a Slack channel and turn issues into Jira tickets. Tokens are stored for sending only and are never shown again, even to admins.</p>
      {error && <p className="error">{error}</p>}
      {msg && <p className="small ok">{msg}</p>}

      <h3>Slack</h3>
      <p className="small">{status(data.slack)}. Every new alert (rating drops, new critical issues, dark web, CERT-In, reassessments due, onboarding decisions) is posted to the channel.</p>
      {isAdmin && (
        <form className="form" onSubmit={run(() => api.setSlack({ webhook_url: slack || null }), 'Slack saved.')} style={{ maxWidth: 'none' }}>
          <label>Incoming webhook URL
            <input type="password" autoComplete="off" value={slack} onChange={(e) => setSlack(e.target.value)}
              placeholder={data.slack.connected ? 'Saved. Paste a new URL to replace it.' : 'https://hooks.slack.com/services/…'} />
          </label>
          <p className="muted small">In Slack, add the "Incoming WebHooks" app to the channel (or create a Slack app with incoming webhooks) and copy its URL.</p>
          <div className="actions" style={{ justifyContent: 'flex-start' }}>
            <button className="btn primary" disabled={!slack}>Save</button>
            {data.slack.connected && <button type="button" className="btn ghost" onClick={run(() => api.testSlack(), 'Test message sent. Check the channel.')}>Send a test message</button>}
            {data.slack.connected && <button type="button" className="btn ghost" onClick={run(() => api.removeIntegration('slack'), 'Slack disconnected.')}>Disconnect</button>}
          </div>
        </form>
      )}

      <h3 style={{ marginTop: 20 }}>Jira</h3>
      <p className="small">{status(data.jira)}. Use "Create Jira issue" on any issue in a company's fix plan.</p>
      {isAdmin && (
        <form className="form" onSubmit={run(() => api.setJira({ ...jira, api_token: jira.api_token || null }), 'Jira saved.')} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Jira Cloud address<input required value={jira.site} onChange={(e) => setJira({ ...jira, site: e.target.value })} placeholder="https://yourcompany.atlassian.net" /></label>
            <label>Project key<input required value={jira.project} onChange={(e) => setJira({ ...jira, project: e.target.value })} placeholder="SEC" /></label>
          </div>
          <div className="form-row">
            <label>Account email<input required type="email" value={jira.email} onChange={(e) => setJira({ ...jira, email: e.target.value })} /></label>
            <label>Issue type<input value={jira.issue_type} onChange={(e) => setJira({ ...jira, issue_type: e.target.value })} placeholder="Task" /></label>
          </div>
          <label>API token
            <input type="password" autoComplete="off" value={jira.api_token} onChange={(e) => setJira({ ...jira, api_token: e.target.value })}
              placeholder={data.jira.connected ? 'Saved. Enter a new token to replace it.' : 'Create one at id.atlassian.com → Security → API tokens'} />
          </label>
          <div className="actions" style={{ justifyContent: 'flex-start' }}>
            <button className="btn primary">Save</button>
            {data.jira.connected && <button type="button" className="btn ghost" onClick={run(() => api.removeIntegration('jira'), 'Jira disconnected.')}>Disconnect</button>}
          </div>
        </form>
      )}
      {!isAdmin && <p className="muted small">Only admins can connect integrations.</p>}
    </section>
  )
}
