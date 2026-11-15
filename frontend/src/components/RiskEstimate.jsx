import { useEffect, useState } from 'react'
import { api } from '../api.js'

const fmt = (crore) => crore >= 1 ? `₹${crore.toLocaleString('en-IN', { maximumFractionDigits: 1 })} crore`
  : `₹${(crore * 100).toLocaleString('en-IN', { maximumFractionDigits: 1 })} lakh`

export default function RiskEstimate({ entityId, version }) {
  const [r, setR] = useState(null)
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  const [show, setShow] = useState(false)
  useEffect(() => { api.getRisk(entityId).then(setR).catch(() => setR(null)) }, [entityId, version])
  if (!r?.expected_loss_crore && r?.expected_loss_crore !== 0) return null

  async function save(e) {
    e.preventDefault()
    setError(null)
    try {
      setR(await api.setRisk(entityId, { revenue_crore: form.revenue ? Number(form.revenue) : null, sensitivity: form.sensitivity }))
      setForm(null)
    } catch (err) { setError(err.message) }
  }

  return (
    <section className="card">
      <div className="section-head">
        <h2>Estimated cyber risk in rupees</h2>
        {!form && <button className="btn ghost tiny" onClick={() => setForm({ revenue: r.revenue_crore ?? '', sensitivity: r.sensitivity })}>Edit inputs</button>}
      </div>
      <div className="stats">
        <div><div className="stat">{fmt(r.expected_loss_crore)}</div><div className="muted small">expected loss per year (range {fmt(r.range_crore[0])} to {fmt(r.range_crore[1])})</div></div>
        <div><div className="stat">{(r.probability * 100).toFixed(1)}%</div><div className="muted small">estimated chance of a breach this year</div></div>
        <div><div className="stat">{fmt(r.impact_crore)}</div><div className="muted small">likely cost if a breach happens</div></div>
      </div>
      {form && (
        <form className="form" onSubmit={save} style={{ maxWidth: 'none' }}>
          <div className="form-row">
            <label>Annual revenue (₹ crore)<input type="number" min="0" step="any" value={form.revenue} onChange={(e) => setForm({ ...form, revenue: e.target.value })} placeholder="Leave blank if unknown" /></label>
            <label>Sensitivity of data they hold for you
              <select value={form.sensitivity} onChange={(e) => setForm({ ...form, sensitivity: e.target.value })}>
                <option value="low">Low (no personal or financial data)</option>
                <option value="standard">Standard</option>
                <option value="high">High (customer personal, health or payment data)</option>
              </select>
            </label>
          </div>
          {error && <p className="error">{error}</p>}
          <div className="actions"><button type="button" className="btn ghost" onClick={() => setForm(null)}>Cancel</button><button className="btn primary">Recalculate</button></div>
        </form>
      )}
      <p className="muted small">
        {r.revenue_crore ? `Based on annual revenue of ₹${r.revenue_crore.toLocaleString('en-IN')} crore. ` : 'Add annual revenue for a size-adjusted estimate. '}
        An illustrative planning estimate, not an insurance figure. <button className="link-btn" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'} assumptions</button>
      </p>
      {show && (
        <ul className="small muted">
          <li>Average breach cost in India: ₹{r.assumptions.breach_cost_crore} crore ({r.assumptions.breach_cost_source}).</li>
          <li>Chance of a breach is {r.assumptions.base_probability_at_700 * 100}% a year at a score of 700, multiplying by about 2.7 for every 250 points lower and falling for higher scores.</li>
          <li>Cost scales with company size as {r.assumptions.size_scaling}, times {r.assumptions.sensitivity_multiplier} for data sensitivity. The range is half to double the central estimate.</li>
        </ul>
      )}
    </section>
  )
}
