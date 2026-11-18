import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { api } from '../api.js'

export default function MfaSetup({ forced = false, onChange }) {
  const [status, setStatus] = useState(null)
  const [setup, setSetup] = useState(null)
  const [qr, setQr] = useState(null)
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState(null)
  const [off, setOff] = useState(null)
  const [error, setError] = useState(null)
  const load = () => api.mfaStatus().then(setStatus).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])
  useEffect(() => { if (setup) QRCode.toDataURL(setup.uri, { margin: 1, width: 200 }).then(setQr).catch(() => setQr(null)) }, [setup])
  if (!status) return error ? <p className="error">{error}</p> : null
  const nice = (m) => m.charAt(0).toUpperCase() + m.slice(1) + '.'

  async function start() { setError(null); try { setSetup(await api.mfaSetup()) } catch (e) { setError(nice(e.message)) } }
  async function enable(e) {
    e.preventDefault(); setError(null)
    try { const r = await api.mfaEnable(code); setCodes(r.recovery_codes); setSetup(null); setCode(''); load() } catch (err) { setError(nice(err.message)) }
  }
  async function disable(e) {
    e.preventDefault(); setError(null)
    try { await api.mfaDisable(off.password, off.code); setOff(null); load(); onChange?.() } catch (err) { setError(nice(err.message)) }
  }

  return (
    <section className="card form">
      <h2>Two-step login</h2>
      {forced && !status.enabled && <p className="banner">Your organisation requires two-step login. Set it up to continue.</p>}
      {codes ? (
        <>
          <p className="strong">Two-step login is on. Save these recovery codes somewhere safe.</p>
          <p className="small">Each code works once if you lose your phone. They will not be shown again.</p>
          <pre className="mono" style={{ columns: 2 }}>{codes.join('\n')}</pre>
          <div className="actions"><button className="btn primary" onClick={() => { setCodes(null); onChange?.() }}>I have saved them</button></div>
        </>
      ) : status.enabled ? (
        <>
          <p className="small"><span className="ok">On.</span> You sign in with your password and a code from your authenticator app. {status.recovery_left} recovery codes left.</p>
          {!status.org_requires && !off && <div className="actions" style={{ justifyContent: 'flex-start' }}><button className="btn ghost" onClick={() => setOff({ password: '', code: '' })}>Turn off</button></div>}
          {status.org_requires && <p className="muted small">Your organisation requires two-step login, so it cannot be turned off.</p>}
          {off && (
            <form onSubmit={disable} className="form">
              <label>Password<input type="password" autoComplete="current-password" required value={off.password} onChange={(e) => setOff({ ...off, password: e.target.value })} /></label>
              <label>Code from your app<input inputMode="numeric" autoComplete="one-time-code" required value={off.code} onChange={(e) => setOff({ ...off, code: e.target.value })} /></label>
              <div className="actions"><button type="button" className="btn ghost" onClick={() => setOff(null)}>Cancel</button><button className="btn primary">Turn off</button></div>
            </form>
          )}
        </>
      ) : setup ? (
        <form onSubmit={enable} className="form">
          <p className="small">1. Scan this with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password or similar).</p>
          {qr && <img src={qr} alt="QR code for your authenticator app" width="200" height="200" />}
          <p className="small muted">Can't scan? Enter this key: <span className="mono">{setup.secret.match(/.{1,4}/g).join(' ')}</span></p>
          <label>2. Enter the 6-digit code it shows<input inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} /></label>
          <div className="actions"><button className="btn primary">Turn on</button></div>
        </form>
      ) : (
        <>
          <p className="small">Protect your account with a code from your phone as well as your password.</p>
          <div className="actions" style={{ justifyContent: 'flex-start' }}><button className="btn primary" onClick={start}>Set up two-step login</button></div>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </section>
  )
}
