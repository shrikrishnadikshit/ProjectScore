export function gradeClass(grade) {
  return grade ? `grade-${grade.toLowerCase()}` : 'grade-none'
}

export function GradeBadge({ grade, size = 'md' }) {
  return <span className={`grade-badge ${size} ${gradeClass(grade)}`}>{grade ?? '–'}</span>
}

// Semicircle gauge for the 300–900 scale.
export function ScoreGauge({ score, grade }) {
  const pct = score == null ? 0 : (score - 300) / 600
  const r = 80
  const circumference = Math.PI * r
  return (
    <div className={`gauge ${gradeClass(grade)}`}>
      <svg viewBox="0 0 200 115" role="img" aria-label={score == null ? 'Not yet scored' : `Score ${score} of 900`}>
        <path d="M20 100 A80 80 0 0 1 180 100" className="gauge-track" />
        <path d="M20 100 A80 80 0 0 1 180 100" className="gauge-fill"
          strokeDasharray={`${circumference * pct} ${circumference}`} />
      </svg>
      <div className="gauge-label">
        <div className="gauge-score">{score ?? '—'}</div>
        <div className="gauge-scale">out of 900</div>
      </div>
    </div>
  )
}
