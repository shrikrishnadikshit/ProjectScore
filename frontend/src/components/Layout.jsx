import { useCallback, useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { api, setUnauthorizedHandler } from '../api.js'
import Login from '../pages/Login.jsx'

export default function Layout() {
  const [user, setUser] = useState(undefined) // undefined = checking, null = signed out
  const [unread, setUnread] = useState(0)
  const refreshAlerts = useCallback(() => { api.alertCount().then((r) => setUnread(r.count)).catch(() => {}) }, [])

  useEffect(() => {
    if (!user) return
    refreshAlerts()
    const t = setInterval(refreshAlerts, 60000)
    return () => clearInterval(t)
  }, [user, refreshAlerts])

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null))
    api.me().then(setUser).catch(() => setUser(null))
  }, [])

  async function signOut() {
    await api.logout().catch(() => {})
    setUser(null)
  }

  if (user === undefined) return null
  if (user === null) return <Login onSignedIn={setUser} />

  return (
    <div className="shell">
      <header className="topbar">
        <NavLink to="/" className="brand">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </span>
          ProjectScore
        </NavLink>
        <nav>
          <NavLink to="/" end>Portfolio</NavLink>
          <NavLink to="/advisory">Advisory</NavLink>
          <NavLink to="/alerts">Alerts{unread > 0 && <span className="nav-badge">{unread}</span>}</NavLink>
          {(user.role === 'admin' || user.role === 'owner') && <NavLink to="/in-depth">In-depth scans</NavLink>}
          <NavLink to="/code-reviews">Code reviews</NavLink>
          {(user.role === 'admin' || user.role === 'owner') && <NavLink to="/team">Team</NavLink>}
          {user.role === 'owner' && <NavLink to="/disputes">Disputes</NavLink>}
          {user.role === 'owner' && <NavLink to="/leads">Leads</NavLink>}
          {user.role === 'owner' && <NavLink to="/opt-outs">Opt-outs</NavLink>}
        </nav>
        <div className="account">
          <NavLink to="/account" className="muted small account-org" title={user.email}>{user.organization}</NavLink>
          <button className="btn ghost small-btn" onClick={signOut} title={user.email}>Sign out</button>
        </div>
      </header>
      <main className="content">
        <Outlet context={{ user, refreshAlerts }} />
      </main>
    </div>
  )
}
