async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  const body = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) {
    const detail = body?.detail
    const message = Array.isArray(detail) ? detail.map((d) => d.msg).join(', ') : detail
    throw new Error(message || `Request failed (${res.status})`)
  }
  return body
}

export const api = {
  listEntities: () => request('/entities'),
  getEntity: (id) => request(`/entities/${id}`),
  getScores: (id) => request(`/entities/${id}/scores`),
  createEntity: (data) => request('/entities', { method: 'POST', body: JSON.stringify(data) }),
  startScan: (id) => request(`/entities/${id}/scan`, { method: 'POST' }),
}

export const FACTOR_LABELS = {
  compromise: 'Compromise & malicious activity',
  vulnerability: 'Vulnerabilities & patching',
  network_exposure: 'Network service exposure',
  identity: 'Identity & credential exposure',
  email_security: 'Email security',
  tls: 'TLS / encryption',
  web_security: 'Web application security',
  dns_health: 'DNS health',
  breach_history: 'Breach & ransomware history',
  brand: 'Brand & impersonation',
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
