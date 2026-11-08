// API types mirroring the Spring Boot DTOs

export interface DashboardStats {
  requestsPerSecond: number
  l1HitRatio: number
  l2HitRatio: number
  avgSigningLatencyMs: number
  errorRate: number
  activeCacheEntries: number
  revokedCertificates: number
  ocspSigningCertDaysRemaining: number
  lastReconciliationOk: boolean
}

export interface CacheEntry {
  cacheKey: string
  thisUpdate: string   // ISO-8601
  nextUpdate: string
  createdAt: string
  responseSizeBytes: number
}

export interface RevocationEvent {
  eventId: string
  eventType: 'CertificateIssued' | 'CertificateRevoked' | 'CertificateHeld' | 'CertificateUnrevoked' | string
  serialNumberHex?: string
  serialNumber?: string
  revocationReason?: string | null
  revocationTime?: string | null
  receivedAt?: string
  processedAt?: string | null
  thisUpdate?: string
  updatedAt?: string
  status?: 'RECEIVED' | 'PROCESSED' | 'FAILED' | string
  errorMessage?: string | null
}

export interface Page<T> {
  content: T[]
  totalElements: number
  totalPages: number
  number: number
  size: number
}

export interface CertStatusResponse {
  serialHex: string
  status: 'GOOD' | 'REVOKED' | 'UNKNOWN'
  revocationTime: string | null
  revocationReason: string | null
  renewalAvailable: boolean
}

export interface RenewRequestResponse {
  requestId: string
  serialHex: string
  kmsStatus: string
  newNotAfter: string
  submittedAt: string
}

export type KmsRevocationReason =
  | 'UNSPECIFIED'
  | 'KEY_COMPROMISE'
  | 'CA_COMPROMISE'
  | 'AFFILIATION_CHANGED'
  | 'SUPERSEDED'
  | 'CESSATION_OF_OPERATION'
  | 'CERTIFICATE_HOLD'
  | 'REMOVE_FROM_CRL'
  | 'PRIVILEGE_WITHDRAWN'
  | 'AA_COMPROMISE'

export interface KmsCertificate {
  serialNumberHex: string
  issuerDn: string
  issuerKeyHashHex: string
  issuerNameHashHex: string
  subjectDn: string
  notBefore: string
  notAfter: string
  status: 'GOOD' | 'REVOKED'
  revocationTime: string | null
  revocationReason: KmsRevocationReason | string | null
  pemEncoded: string
  sequence: number
}

export interface OcspTestResult {
  serialHex: string
  method: string
  includeNonce: boolean
  nonceSent: string
  nonceEchoed: string
  nonceMatched: boolean
  cacheVerdict: string
  l2Hit: boolean
  latencyMs: number
  certStatus: 'GOOD' | 'REVOKED' | 'UNKNOWN'
  revocationTime: string
  revocationReason: string
  thisUpdate: string
  nextUpdate: string
  responseSizeBytes: number
  base64UrlPath: string
  opensslCommand: string
  error?: string
}
