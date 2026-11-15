import { NavLink, Outlet } from 'react-router-dom'

export default function Layout() {
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
        </nav>
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
