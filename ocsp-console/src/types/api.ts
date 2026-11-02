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
  eventType: 'CertificateIssued' | 'CertificateRevoked' | 'CertificateHeld' | 'CertificateUnrevoked'
  serialNumberHex: string
  revocationReason: string | null
  revocationTime: string | null
  receivedAt: string
  processedAt: string | null
  status: 'RECEIVED' | 'PROCESSED' | 'FAILED'
  errorMessage: string | null
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
