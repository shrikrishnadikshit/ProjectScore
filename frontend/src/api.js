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
  entityVendors: (id, refresh) => request(`/entities/${id}/vendors${refresh ? '?refresh_now=true' : ''}`),
  fourthParties: () => request('/fourth-parties'),
  importEntities: (csv, scan = true) => request('/entities/import', { method: 'POST', body: JSON.stringify({ csv, scan }) }),
  listVendorShares: (id) => request(`/entities/${id}/vendor-shares`),
  createVendorShare: (id, data) => request(`/entities/${id}/vendor-shares`, { method: 'POST', body: JSON.stringify(data) }),
  revokeVendorShare: (id) => request(`/vendor-shares/${id}/revoke`, { method: 'POST' }),
  publicVendorShare: (token) => request(`/public/vendor-share/${encodeURIComponent(token)}`),
  replyVendorShare: (token, fid, status, comment) => request(`/public/vendor-share/${encodeURIComponent(token)}/findings/${fid}`, { method: 'PUT', body: JSON.stringify({ status, comment }) }),
  rescanVendorShare: (token) => request(`/public/vendor-share/${encodeURIComponent(token)}/rescan`, { method: 'POST' }),
  entityRansomware: (id) => request(`/entities/${id}/ransomware`),
  portfolioRansomware: () => request('/ransomware'),
  threatEvents: (days = 30) => request(`/threat-events?days=${days}`),
  listCertificates: (id) => request(`/entities/${id}/certificates`),
  addCertificate: (id, data) => request(`/entities/${id}/certificates`, { method: 'POST', body: JSON.stringify(data) }),
  updateCertificate: (cid, data) => request(`/certificates/${cid}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteCertificate: (cid) => request(`/certificates/${cid}`, { method: 'DELETE' }),
  portfolioCertificates: () => request('/certificates'),
  entityAssets: (id) => request(`/entities/${id}/assets`),
  getPolicy: () => request('/policy'),
  setPolicy: (rules) => request('/policy', { method: 'PUT', body: JSON.stringify({ rules }) }),
  policyCompliance: () => request('/policy/compliance'),
  getOrgSettings: () => request('/org-settings'),
  setOrgSettings: (data) => request('/org-settings', { method: 'PUT', body: JSON.stringify(data) }),
  deleteAccount: (password) => request('/account/delete', { method: 'POST', body: JSON.stringify({ password }) }),
  attackPaths: (id) => request(`/entities/${id}/attack-paths`),
  redTeamConfig: () => request('/red-team/config'),
  listRedTeam: () => request('/red-team'),
  getRedTeam: (id) => request(`/red-team/${id}`),
  requestRedTeam: (data) => request('/red-team', { method: 'POST', body: JSON.stringify(data) }),
  pauseRedTeam: (id, paused, reason) => request(`/red-team/${id}/pause`, { method: 'POST', body: JSON.stringify({ paused, reason }) }),
  cancelRedTeam: (id, reason) => request(`/red-team/${id}/cancel`, { method: 'POST', body: JSON.stringify({ reason }) }),
  redTeamFindingStatus: (id, fid, status, note) => request(`/red-team/${id}/findings/${fid}/status`, { method: 'POST', body: JSON.stringify({ status, note }) }),
  updateRedTeam: (id, data) => request(`/red-team/${id}/update`, { method: 'POST', body: JSON.stringify(data) }),
  addRedTeamFinding: (id, data) => request(`/red-team/${id}/findings`, { method: 'POST', body: JSON.stringify(data) }),
  listQuestionnaires: (id) => request(`/entities/${id}/questionnaires`),
  sendQuestionnaire: (id, data) => request(`/entities/${id}/questionnaires`, { method: 'POST', body: JSON.stringify(data) }),
  getQuestionnaire: (id) => request(`/questionnaires/${id}`),
  reviewQuestionnaire: (id, note) => request(`/questionnaires/${id}/review`, { method: 'POST', body: JSON.stringify({ note }) }),
  publicQuestionnaire: (token) => request(`/public/questionnaire/${encodeURIComponent(token)}`),
  savePublicQuestionnaire: (token, answers, submit) => request(`/public/questionnaire/${encodeURIComponent(token)}`, { method: 'PUT', body: JSON.stringify({ answers, submit }) }),
  getRisk: (id) => request(`/entities/${id}/risk`),
  setRisk: (id, data) => request(`/entities/${id}/risk`, { method: 'PUT', body: JSON.stringify(data) }),
  listApiKeys: () => request('/api-keys'),
  createApiKey: (name) => request('/api-keys', { method: 'POST', body: JSON.stringify({ name }) }),
  revokeApiKey: (id) => request(`/api-keys/${id}/revoke`, { method: 'POST' }),
  ssoProviders: () => request('/auth/sso/providers'),
  listIncidents: (id) => request(`/entities/${id}/incidents`),
  recordIncident: (id, data) => request(`/entities/${id}/incidents`, { method: 'POST', body: JSON.stringify(data) }),
  remediationPlan: (id) => request(`/entities/${id}/remediation`),
  advisoryServices: () => request('/advisory/services'),
  requestAdvisory: (id, data) => request(`/entities/${id}/advisory`, { method: 'POST', body: JSON.stringify(data) }),
  listAdvisory: () => request('/advisory'),
  listCodeReviews: () => request('/code-reviews'),
  getCodeReview: (id) => request(`/code-reviews/${id}`),
  startGitReview: (url, confirm) => request('/code-reviews/git', { method: 'POST', body: JSON.stringify({ url, confirm }) }),
  uploadCodeReview: async (file, confirm) => {
    const form = new FormData()
    form.append('file', file)
    form.append('confirm', confirm ? 'true' : 'false')
    const res = await fetch('/api/code-reviews/upload', { method: 'POST', body: form, credentials: 'same-origin' })
    const body = await res.json().catch(() => null)
    if (!res.ok) throw new Error(body?.detail || `Upload failed (${res.status})`)
    return body
  },
  updateAdvisory: (id, status, owner_note) => request(`/advisory/${id}`, { method: 'POST', body: JSON.stringify({ status, owner_note }) }),
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
