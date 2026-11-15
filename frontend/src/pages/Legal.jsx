import { Link, useLocation } from 'react-router-dom'
import { DPA, LEGAL_DRAFT, PRIVACY, TERMS, UPDATED } from '../legal.js'
import PublicFooter from '../components/PublicFooter.jsx'

const PAGES = {
  '/terms': ['Terms of service', TERMS],
  '/privacy': ['Privacy policy', PRIVACY],
  '/dpa': ['Data processing agreement', DPA],
}

export default function Legal() {
  const { pathname } = useLocation()
  const [title, sections] = PAGES[pathname] || PAGES['/terms']
  return (
    <div className="public">
      <Link to="/" className="brand">ProjectScore</Link>
      <h1>{title}</h1>
      <p className="muted small">Last updated: {UPDATED}{LEGAL_DRAFT && ' · Draft pending legal review'}</p>
      {sections.map(([h, text]) => (
        <section key={h}>
          <h2>{h}</h2>
          <p>{text}</p>
        </section>
      ))}
      <PublicFooter />
    </div>
  )
}
