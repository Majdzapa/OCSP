import axios from 'axios'
import type {
  DashboardStats,
  CacheEntry,
  RevocationEvent,
  Page,
  CertStatusResponse,
  RenewRequestResponse,
  KmsCertificate,
  OcspTestResult,
} from '../types/api'

const api = axios.create({
  baseURL: '/api/v1/admin',
  headers: { 'Content-Type': 'application/json' },
})

// ---- Dev-only token bootstrap ----
// There is no interactive OIDC login yet. In `npm run dev`, fetch a
// client_credentials token from the local ocsp-auth server (proxied by Vite at
// /oauth2). import.meta.env.DEV is false in production builds, so this code and
// the dev secret are stripped out.
let devTokenPromise: Promise<string | null> | null = null

async function fetchDevToken(): Promise<string | null> {
  if (!import.meta.env.DEV) return null
  const clientId = import.meta.env.VITE_DEV_CLIENT_ID ?? 'ocsp-console'
  const clientSecret = import.meta.env.VITE_DEV_CLIENT_SECRET ?? 'secret'
  const res = await axios.post(
    '/oauth2/token',
    new URLSearchParams({ grant_type: 'client_credentials', scope: 'ocsp.admin' }),
    { auth: { username: clientId, password: clientSecret } },
  )
  const token: string = res.data.access_token
  localStorage.setItem('access_token', token)
  return token
}

function getDevToken(): Promise<string | null> {
  devTokenPromise ??= fetchDevToken().finally(() => { devTokenPromise = null })
  return devTokenPromise
}

// Attach bearer token from localStorage (set after OIDC login flow)
api.interceptors.request.use(async (config) => {
  let token = localStorage.getItem('access_token')
  if (!token && import.meta.env.DEV) token = await getDevToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Dev only: on 401 (expired/invalid token) fetch a fresh token and retry once.
api.interceptors.response.use(undefined, async (error) => {
  const original = error.config
  if (import.meta.env.DEV && error.response?.status === 401 && original && !original._retried) {
    original._retried = true
    localStorage.removeItem('access_token')
    const token = await getDevToken()
    if (token) {
      original.headers.Authorization = `Bearer ${token}`
      return api(original)
    }
  }
  return Promise.reject(error)
})

// ---- Dashboard ----
export const getDashboardStats = (): Promise<DashboardStats> =>
  api.get('/dashboard/stats').then((r) => r.data)

// ---- Cache ----
export const getCacheEntries = (page = 0, size = 25): Promise<Page<CacheEntry>> =>
  api.get('/cache', { params: { page, size } }).then((r) => r.data)

export const findCacheBySerial = (serialHex: string): Promise<CacheEntry> =>
  api.get(`/cache/serial/${serialHex}`).then((r) => r.data)

export const invalidateCacheEntry = (cacheKey: string): Promise<void> =>
  api.delete(`/cache/${cacheKey}`).then(() => undefined)

// ---- Revocation Activity ----
export const getRevocationEvents = (page = 0, size = 25): Promise<Page<RevocationEvent>> =>
  api.get('/revocations', { params: { page, size } }).then((r) => r.data)

// ---- Cert Status Check ----
export const checkCertStatus = (serialHex: string): Promise<CertStatusResponse> =>
  api.get(`/cert-check/${serialHex}`).then((r) => r.data)

export const requestCertRenewal = (serialHex: string, reason: string): Promise<RenewRequestResponse> =>
  api.post(`/cert-check/${serialHex}/renew-request`, { reason }).then((r) => r.data)

export const testOcspRequest = (
  serialHex: string,
  includeNonce: boolean,
  method: 'POST' | 'GET' = 'POST'
): Promise<OcspTestResult> =>
  api.post('/cert-check/test-request', { serialHex, includeNonce, method }).then((r) => r.data)

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

export const triggerKmsRevocationJob = (): Promise<{ status: string }> =>
  kmsApi.post('/jobs/revocation/run').then((r) => r.data)


