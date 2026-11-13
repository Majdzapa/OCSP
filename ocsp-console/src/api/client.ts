import axios from 'axios'
import type {
  DashboardStats,
  RevocationEvent,
  Page,
  CertStatusResponse,
  RenewRequestResponse,
  KmsCertificate,
  OcspTestResult,
} from '../types/api'

// API client for ocsp-responder (protected with X-API-KEY or Basic Auth)
const api = axios.create({
  baseURL: '/api/v1/admin',
  headers: {
    'Content-Type': 'application/json',
    'X-API-KEY': 'incert-admin-secret-key',
  },
})

// Attach bearer token if available in localStorage
api.interceptors.request.use(async (config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

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
