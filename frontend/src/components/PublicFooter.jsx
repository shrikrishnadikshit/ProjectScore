import { Link } from 'react-router-dom'

export default function PublicFooter() {
  return (
    <footer className="public-footer small muted">
      <Link to="/methodology">How ratings work</Link>
      <Link to="/scanner">About our scanner and opt-out</Link>
      <Link to="/privacy">Privacy</Link>
      <Link to="/privacy-request">Privacy request</Link>
      <Link to="/terms">Terms</Link>
      <Link to="/dpa">Data processing</Link>
    </footer>
  )
}
