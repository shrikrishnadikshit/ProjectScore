export class AuthError extends Error {}

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options,
  })
  if (res.status === 401 && !path.startsWith('/auth/')) {
    onUnauthorized()
    throw new AuthError('Please sign in again')
  }
  const body = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) {
    const detail = body?.detail
    const message = Array.isArray(detail) ? detail.map((d) => d.msg).join(', ') : detail
    throw new Error(message || `Request failed (${res.status})`)
  }
  return body
}

export const api = {
  me: () => request('/auth/me'),
  login: (email, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  changePassword: (current_password, new_password) =>
    request('/auth/password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),
  listUsers: () => request('/users'),
  requestOptOut: (data) => request('/public/opt-out', { method: 'POST', body: JSON.stringify(data) }),
  listOptOuts: () => request('/opt-outs'),
  listVerifications: () => request('/verifications'),
  startVerification: (domain) => request('/verifications', { method: 'POST', body: JSON.stringify({ domain }) }),
  checkVerification: (id) => request(`/verifications/${id}/check`, { method: 'POST' }),
  activeConfig: () => request('/active-scans/config'),
  listActiveScans: () => request('/active-scans'),
  getActiveScan: (id) => request(`/active-scans/${id}`),
  startActiveScan: (data) => request('/active-scans', { method: 'POST', body: JSON.stringify(data) }),
  decideOptOut: (id, status) => request(`/opt-outs/${id}`, { method: 'POST', body: JSON.stringify({ status }) }),
  listOrganizations: () => request('/organizations'),
  addUser: (data) => request('/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id, data) => request(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  resetPassword: (id) => request(`/users/${id}/reset-password`, { method: 'POST' }),
  listEntities: () => request('/entities'),
  getEntity: (id) => request(`/entities/${id}`),
  getScores: (id) => request(`/entities/${id}/scores`),
  createEntity: (data) => request('/entities', { method: 'POST', body: JSON.stringify(data) }),
  startScan: (id) => request(`/entities/${id}/scan`, { method: 'POST' }),
  disputeFinding: (id, reason) => request(`/findings/${id}/disputes`, { method: 'POST', body: JSON.stringify({ reason }) }),
  entityDisputes: (id) => request(`/entities/${id}/disputes`),
  listDisputes: () => request('/disputes'),
  decideDispute: (id, status, note) => request(`/disputes/${id}`, { method: 'POST', body: JSON.stringify({ status, note }) }),
  requestFreeReport: (data) => request('/public/free-report', { method: 'POST', body: JSON.stringify(data) }),
  getFreeReport: (token) => request(`/public/free-report/${encodeURIComponent(token)}`),
  entityFrameworks: (id) => request(`/entities/${id}/frameworks`),
  listAlerts: () => request('/alerts'),
  alertCount: () => request('/alerts/unread-count'),
  readAlert: (id) => request(`/alerts/${id}/read`, { method: 'POST' }),
  readAllAlerts: () => request('/alerts/read-all', { method: 'POST' }),
  industries: () => request('/industries'),
  benchmark: (id) => request(`/entities/${id}/benchmark`),
  setIndustry: (id, industry) => request(`/entities/${id}/industry`, { method: 'PATCH', body: JSON.stringify({ industry }) }),
  listLeads: () => request('/free-reports'),
  publicDispute: (data) => request('/public/disputes', { method: 'POST', body: JSON.stringify(data) }),
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
