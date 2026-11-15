export default function History({ scores }) {
  if (scores.length < 2) {
    return <p className="muted">The trend appears after the second scan.</p>
  }
  const w = 560, h = 140, pad = 24
  const xs = scores.map((_, i) => pad + (i * (w - 2 * pad)) / (scores.length - 1))
  const y = (v) => h - pad - ((v - 300) / 600) * (h - 2 * pad)
  const points = scores.map((s, i) => `${xs[i]},${y(s.overall)}`).join(' ')
  return (
    <svg className="history" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="Score history">
      {[300, 600, 900].map((v) => (
        <g key={v}>
          <line x1={pad} x2={w - pad} y1={y(v)} y2={y(v)} className="history-grid" />
          <text x={2} y={y(v) + 4} className="history-axis">{v}</text>
        </g>
      ))}
      <polyline points={points} className="history-line" />
      {scores.map((s, i) => (
        <circle key={i} cx={xs[i]} cy={y(s.overall)} r="3.5" className="history-dot">
          <title>{`${new Date(s.created_at).toLocaleDateString()}: ${s.overall} (${s.grade})`}</title>
        </circle>
      ))}
    </svg>
  )
}
