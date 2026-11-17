// API types mirroring the Spring Boot DTOs

export interface DashboardStats {
  requestsPerSecond: number
  totalRequests?: number
  avgSigningLatencyMs: number
  errorRate: number
  revokedCertificates: number
  goodCertificates?: number
  totalCertificates?: number
  ocspSigningCertDaysRemaining: number
  lastReconciliationOk: boolean
  cachingEnabled?: boolean
  architecture?: string
  messagingBroker?: string
  tlsEnabled?: boolean
  ocspLoginTlsEnabled?: boolean
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
  cacheKey?: string
  method: string
  includeNonce: boolean
  nonceSent?: string | null
  nonceEchoed?: string | null
  nonceMatched?: boolean
  cacheVerdict?: string
  l2Hit?: boolean
  latencyMs: number
  certStatus: 'GOOD' | 'REVOKED' | 'UNKNOWN' | string
  revocationTime?: string | null
  revocationReason?: string | null
  thisUpdate?: string | null
  nextUpdate?: string | null
  responseSizeBytes?: number
  base64UrlPath?: string
  opensslCommand?: string | null
  error?: string | null
}

export interface AuthConfig {
  authMode: 'SELF_MANAGED' | 'KEYCLOAK' | 'KEYCLOCK' | string
  isKeycloak: boolean
  tlsEnabled?: boolean
  keycloak?: {
    authServerUrl: string
    realm: string
    clientId: string
  }
}

export interface AuthUser {
  authenticated: boolean
  username: string
  roles?: Array<string | { authority?: string }>
  authMode?: string
  tlsEnabled?: boolean
  apiKey?: string
  basicAuth?: string
  token?: string
}

export interface LoginResponse {
  authenticated: boolean
  username?: string
  roles?: Array<string | { authority?: string }>
  authMode?: string
  tlsEnabled?: boolean
  apiKey?: string
  basicAuth?: string
  token?: string
  authType?: string
  message?: string
}

export interface InboxEventItem {
  eventId: string
  eventType: string
  certificateSerial: string
  status: 'GOOD' | 'REVOKED' | string
  revocationReason?: string | null
  revocationTime?: string | null
  sequence: number
  payload?: string | null
  receivedAt: string
  processedAt?: string | null
  processingStatus: 'RECEIVED' | 'PROCESSED' | 'DUPLICATE' | 'SKIPPED' | 'FAILED' | string
  errorMessage?: string | null
  deliveryTag?: number | null
  consumerQueue?: string | null
  redelivered?: boolean | null
}

export interface ReconciliationReport {
  synchronized: boolean
  kmsTotal: number
  responderTotal: number
  inboxEventsReceived: number
  matchedCount: number
  missingCount: number
  missingSerials: string[]
  mismatchCount: number
  statusMismatches: Array<{
    serialNumberHex: string
    kmsStatus: string
    responderStatus: string
    subjectDn?: string
  }>
  verifiedAt: string
}

export interface SigningCertificateDto {
  id: number
  alias: string
  keyLabel: string
  subjectDn: string
  issuerDn: string
  serialNumber: string
  notBefore: string
  notAfter: string
  signatureAlgorithm: string
  active: boolean
  daysUntilExpiry: number
  expired: boolean
  createdAt: string
  activatedAt?: string | null
  certificatePem: string
}

export interface AddSigningCertificateRequest {
  alias: string
  keyLabel?: string
  certificatePem: string
  activateImmediately?: boolean
  signatureAlgorithm?: string
}

export interface HsmInfoDto {
  signerType: string
  pkcs11Library: string
  tokenLabel: string
  slotIndex: number
  activeKeyLabel: string
  tokenAliases: string[]
  keyAlgorithms?: Record<string, string>
  supportedSignatureAlgorithms?: Record<string, string[]>
}

export interface GenerateCsrRequest {
  keyLabel: string
  subjectDn: string
  keyAlgorithm: 'RSA' | 'EC'
  keySize: number
  reuseExistingKey: boolean
}

export interface GenerateCsrResponse {
  keyLabel: string
  subjectDn: string
  keyAlgorithm: string
  csrPem: string
}
