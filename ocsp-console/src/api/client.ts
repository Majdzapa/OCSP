import axios from 'axios'
import type {
  DashboardStats,
  RevocationEvent,
  Page,
  CertStatusResponse,
  RenewRequestResponse,
  KmsCertificate,
  OcspTestResult,
  AuthUser,
  LoginResponse,
  InboxEventItem,
  ReconciliationReport,
  AuthConfig,
  SigningCertificateDto,
  AddSigningCertificateRequest,
} from '../types/api'

// API client for ocsp-responder (protected with X-API-KEY, Basic Auth, or Keycloak Bearer token)
export const api = axios.create({
  baseURL: '/api/v1/admin',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Dynamically attach credentials from localStorage
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ocsp_bearer_token')
  const apiKey = localStorage.getItem('ocsp_api_key')
  const basicAuth = localStorage.getItem('ocsp_basic_auth')

  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`
  } else if (apiKey) {
    config.headers['X-API-KEY'] = apiKey
  } else if (basicAuth) {
    config.headers['Authorization'] = basicAuth
  }
  return config
})

// Auto logout on 401 Unauthorized
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('ocsp_auth_user')
      localStorage.removeItem('ocsp_api_key')
      localStorage.removeItem('ocsp_basic_auth')
      localStorage.removeItem('ocsp_bearer_token')
      window.dispatchEvent(new CustomEvent('ocsp:unauthorized'))
    }
    return Promise.reject(error)
  }
)

// ---- Authentication ----
const authApi = axios.create({
  baseURL: '/api/v1/auth',
  headers: { 'Content-Type': 'application/json' },
})

export const getAuthConfig = async (): Promise<AuthConfig> => {
  const res = await authApi.get<AuthConfig>('/config')
  return res.data
}

export const loginWithCredentials = async (username: string, password: string): Promise<LoginResponse> => {
  const res = await authApi.post<LoginResponse>('/login', { username, password })
  return res.data
}

export const loginWithApiKey = async (apiKey: string): Promise<LoginResponse> => {
  const res = await authApi.post<LoginResponse>('/login', { apiKey })
  return res.data
}

export const loginWithBearerToken = async (token: string): Promise<LoginResponse> => {
  const res = await authApi.post<LoginResponse>('/login', { token })
  return res.data
}

export const exchangeKeycloakCredentials = async (
  authServerUrl: string,
  realm: string,
  clientId: string,
  username: string,
  password: string
): Promise<string> => {
  const tokenUrl = `${authServerUrl}/realms/${realm}/protocol/openid-connect/token`
  const params = new URLSearchParams()
  params.append('client_id', clientId)
  params.append('grant_type', 'password')
  params.append('username', username)
  params.append('password', password)

  const response = await axios.post<{ access_token: string }>(tokenUrl, params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return response.data.access_token
}

export const getAuthMe = async (): Promise<AuthUser> => {
  const token = localStorage.getItem('ocsp_bearer_token')
  const apiKey = localStorage.getItem('ocsp_api_key')
  const basicAuth = localStorage.getItem('ocsp_basic_auth')
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  else if (apiKey) headers['X-API-KEY'] = apiKey
  else if (basicAuth) headers['Authorization'] = basicAuth

  const res = await authApi.get<AuthUser>('/me', { headers })
  return res.data
}

// API client for ocsp-client testing service
const ocspClientApi = axios.create({
  baseURL: '/api/v1/client',
  headers: { 'Content-Type': 'application/json' },
})

// ---- Dashboard ----
export const getDashboardStats = (): Promise<DashboardStats> =>
  api.get('/dashboard/stats').then((r) => r.data)

// ---- Revocation Activity ----
export const getRevocationEvents = (page = 0, size = 25): Promise<Page<RevocationEvent>> =>
  api.get('/revocations', { params: { page, size } }).then((r) => r.data)

// ---- Cert Status Check (Database status check in ocsp-responder) ----
export const checkCertStatus = (serialHex: string): Promise<CertStatusResponse> =>
  api.get(`/cert-check/${serialHex}`).then((r) => r.data)

export const requestCertRenewal = (serialHex: string, reason: string): Promise<RenewRequestResponse> =>
  api.post(`/cert-check/${serialHex}/renew-request`, { reason }).then((r) => r.data)

// ---- Live RFC 6960 OCSP Request Test (Dispatched via ocsp-client) ----
export const testOcspRequest = (
  serialHex: string,
  includeNonce: boolean,
  method: 'POST' | 'GET' = 'POST'
): Promise<OcspTestResult> =>
  ocspClientApi.post('/check', { serialHex, includeNonce, method }).then((r) => {
    const data = r.data
    return {
      serialHex: data.serialHex,
      certStatus: data.certStatus,
      revocationTime: data.revocationTime,
      revocationReason: data.revocationReason,
      thisUpdate: data.thisUpdate,
      nextUpdate: data.nextUpdate,
      includeNonce: data.includeNonce,
      nonceSent: data.nonceSent,
      nonceEchoed: data.nonceEchoed,
      nonceMatched: data.includeNonce ? (data.nonceSent === data.nonceEchoed) : true,
      signatureValid: data.valid,
      latencyMs: data.latencyMs,
      method: data.method || method,
      httpMethod: data.method || method,
      responseSizeBytes: data.responseSizeBytes,
      opensslCommand: `openssl ocsp -issuer data/pki/intermediate-ca-cert.pem -serial 0x${data.serialHex} -url ${data.responderUrl} -CAfile data/pki/ca-chain.pem -resp_text${data.includeNonce ? ' -nonce' : ' -no_nonce'}`,
      cacheVerdict: 'DIRECT_SIGNING (SoftHSM2 PKCS#11)',
      error: data.error,
    }
  })

// ---- Inbox & Reconciliation (Responder) ----
export const getInboxEvents = (
  page = 0,
  size = 50,
  serial?: string
): Promise<{ events: InboxEventItem[]; total: number; page: number; size: number }> =>
  api.get('/inbox', { params: { page, size, serial } }).then((r) => r.data)

export const getInboxStats = (): Promise<{
  totalReceived: number
  processed: number
  duplicate: number
  skipped: number
  failed: number
}> => api.get('/inbox/stats').then((r) => r.data)

export const verifyReconciliation = (): Promise<ReconciliationReport> =>
  api.get('/reconciliation/verify').then((r) => r.data)

// ---- KMS Simulator (Certificate Inventory & Lifecycle) ----
const kmsApi = axios.create({
  baseURL: '/api/kms',
  headers: { 'Content-Type': 'application/json' },
})

export const getKmsCertificates = (): Promise<KmsCertificate[]> =>
  kmsApi.get('/certificates').then((r) => r.data)

export const revokeKmsCertificate = (
  serialHex: string,
  reason: string = 'KEY_COMPROMISE'
): Promise<KmsCertificate> =>
  kmsApi.post(`/certificates/${serialHex}/revoke`, null, { params: { reason } }).then((r) => r.data)

export const unrevokeKmsCertificate = (serialHex: string): Promise<KmsCertificate> =>
  kmsApi.post(`/certificates/${serialHex}/unrevoke`).then((r) => r.data)

export const updateKmsCertificateStatus = (
  serialHex: string,
  status: 'GOOD' | 'REVOKED' | 'CERTIFICATE_HOLD',
  reason?: string,
  revocationTime?: string
): Promise<KmsCertificate> =>
  kmsApi.post(`/certificates/${serialHex}/status`, { status, reason, revocationTime }).then((r) => r.data)

export const getKmsSyncStatus = (): Promise<{
  totalCertificates: number
  goodCertificates: number
  revokedCertificates: number
  totalOutboxEvents: number
  sentOutboxEvents: number
  pendingOutboxEvents: number
}> => kmsApi.get('/audit/sync-status').then((r) => r.data)

export const syncAllKmsCertificates = (): Promise<{
  status: string
  certificatesQueued: number
  message: string
}> => kmsApi.post('/audit/sync-all').then((r) => r.data)

export const triggerKmsRevocationJob = (): Promise<{ status: string }> =>
  kmsApi.post('/jobs/revocation/run').then((r) => r.data)

// ---- Signing Certificates Management ----
export const getSigningCertificates = (): Promise<SigningCertificateDto[]> =>
  api.get('/signing-certificates').then((r) => r.data)

export const getActiveSigningCertificate = (): Promise<SigningCertificateDto> =>
  api.get('/signing-certificates/active').then((r) => r.data)

export const addSigningCertificate = (
  req: AddSigningCertificateRequest
): Promise<SigningCertificateDto> =>
  api.post('/signing-certificates', req).then((r) => r.data)

export const activateSigningCertificate = (id: number): Promise<SigningCertificateDto> =>
  api.put(`/signing-certificates/${id}/activate`).then((r) => r.data)

export const deleteSigningCertificate = (id: number): Promise<void> =>
  api.delete(`/signing-certificates/${id}`).then((r) => r.data)
