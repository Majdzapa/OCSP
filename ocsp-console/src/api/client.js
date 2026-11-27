import axios from 'axios';
// API client for ocsp-responder (protected with Basic Auth or Keycloak Bearer token)
export const api = axios.create({
    baseURL: '/api/v1/admin',
    headers: {
        'Content-Type': 'application/json',
    },
});
// Dynamically attach Bearer JWT from localStorage
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('ocsp_bearer_token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
});
export const clearAuthStorage = () => {
    localStorage.removeItem('ocsp_auth_user');
    localStorage.removeItem('ocsp_basic_auth');
    localStorage.removeItem('ocsp_bearer_token');
    localStorage.removeItem('ocsp_id_token');
    sessionStorage.clear();
    delete api.defaults.headers.common['Authorization'];
    delete authApi.defaults.headers.common['Authorization'];
    delete ocspClientApi.defaults.headers.common['Authorization'];
};
// Auto logout on 401 Unauthorized
api.interceptors.response.use((response) => response, (error) => {
    if (error.response?.status === 401) {
        clearAuthStorage();
        window.dispatchEvent(new CustomEvent('ocsp:unauthorized'));
    }
    return Promise.reject(error);
});
// ---- Authentication ----
const authApi = axios.create({
    baseURL: '/api/v1/auth',
    headers: { 'Content-Type': 'application/json' },
});
export const getAuthConfig = async () => {
    const res = await authApi.get('/config');
    return res.data;
};
export const loginWithCredentials = async (username, password) => {
    const res = await authApi.post('/login', { username, password });
    return res.data;
};
export const loginWithMtlsCert = async () => {
    const res = await authApi.post('/login/mtls');
    return res.data;
};
export const loginWithBearerToken = async (token) => {
    // The responder authenticates the Bearer token from the Authorization header.
    // The token is not in localStorage yet at this point, so it must be sent explicitly.
    const res = await authApi.post('/login', {}, {
        headers: { Authorization: `Bearer ${token}` },
    });
    return res.data;
};
export const getAuthMe = async () => {
    const token = localStorage.getItem('ocsp_bearer_token');
    const headers = {};
    if (token)
        headers['Authorization'] = `Bearer ${token}`;
    const res = await authApi.get('/me', { headers });
    return res.data;
};
// API client for OCSP client testing endpoint (hosted on ocsp-responder under /api/v1/client)
const ocspClientApi = axios.create({
    baseURL: '/api/v1/client',
    headers: { 'Content-Type': 'application/json' },
});
ocspClientApi.interceptors.request.use((config) => {
    const token = localStorage.getItem('ocsp_bearer_token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
});
// ---- Dashboard ----
export const getDashboardStats = () => api.get('/dashboard/stats').then((r) => r.data);
// ---- Revocation Activity ----
export const getRevocationEvents = (page = 0, size = 25) => api.get('/revocations', { params: { page, size } }).then((r) => r.data);
// ---- Cert Status Check (Database status check in ocsp-responder) ----
export const checkCertStatus = (serialHex) => api.get(`/cert-check/${serialHex}`).then((r) => r.data);
// ---- Replicated Certificates Inventory (Received from RabbitMQ) ----
export const getReplicatedCertificates = () => api.get('/certificates').then((r) => r.data);
// ---- Live RFC 6960 OCSP Request Test (Dispatched via ocsp-responder /api/v1/client) ----
export const getClientInfo = () => ocspClientApi.get('/info').then((r) => r.data);
export const getClientPresets = () => ocspClientApi.get('/presets').then((r) => r.data);
export const testOcspRequest = (serialHex, includeNonce, method = 'POST', issuerPem) => ocspClientApi.post('/check', {
    serialHex,
    includeNonce,
    method,
    ...(issuerPem?.trim() ? { issuerPem: issuerPem.trim() } : {}),
}).then((r) => {
    const data = r.data;
    return {
        serialHex: data.serialHex,
        certStatus: data.certStatus,
        revocationTime: data.revocationTime,
        revocationReason: data.revocationReason,
        thisUpdate: data.thisUpdate,
        nextUpdate: data.nextUpdate,
        producedAt: data.producedAt,
        responderId: data.responderId,
        signerSubject: data.signerSubject,
        responseStatus: data.responseStatus,
        httpStatus: data.httpStatus,
        includeNonce: data.includeNonce,
        nonceSent: data.nonceSent,
        nonceEchoed: data.nonceEchoed,
        nonceMatched: data.includeNonce ? (data.nonceSent === data.nonceEchoed) : true,
        signatureValid: data.valid,
        latencyMs: data.latencyMs,
        method: data.method || method,
        httpMethod: data.method || method,
        responseSizeBytes: data.responseSizeBytes,
        opensslCommand: data.opensslCommand ?? null,
        unknownReason: data.unknownReason ?? null,
        issuerNameHashHex: data.issuerNameHashHex ?? null,
        issuerKeyHashHex: data.issuerKeyHashHex ?? null,
        checks: data.checks ?? [],
        cacheVerdict: data.cacheVerdict ?? 'DIRECT_SIGNING',
        error: data.error,
    };
});
// ---- Inbox & Reconciliation (Responder) ----
export const getInboxEvents = (page = 0, size = 50, serial) => api.get('/inbox', { params: { page, size, serial } }).then((r) => r.data);
export const getInboxStats = () => api.get('/inbox/stats').then((r) => r.data);
export const verifyReconciliation = () => api.get('/reconciliation/verify').then((r) => r.data);
export const replayMissingEventsViaRabbitMq = () => api.post('/reconciliation/replay').then((r) => r.data);
// ---- Signing Certificates Management ----
export const getSigningCertificates = () => api.get('/signing-certificates').then((r) => r.data);
export const getActiveSigningCertificate = () => api.get('/signing-certificates/active').then((r) => r.data);
export const addSigningCertificate = (req) => api.post('/signing-certificates', req).then((r) => r.data);
export const activateSigningCertificate = (id) => api.put(`/signing-certificates/${id}/activate`).then((r) => r.data);
export const deactivateSigningCertificate = (id) => api.put(`/signing-certificates/${id}/deactivate`).then((r) => r.data);
export const deleteSigningCertificate = (id) => api.delete(`/signing-certificates/${id}`).then((r) => r.data);
export const getHsmInfo = () => api.get('/signing-certificates/hsm-info').then((r) => r.data);
export const getSigningProviders = () => api.get('/signing-certificates/providers').then((r) => r.data);
export const getProviderCapabilities = (providerId) => api.get(`/signing-certificates/providers/${encodeURIComponent(providerId)}/capabilities`).then((r) => r.data);
export const checkSigningAlgorithm = (req) => api.post('/signing-certificates/check-algorithm', req).then((r) => r.data);
export const generateSigningCsr = (req) => api.post('/signing-certificates/csr', req).then((r) => r.data);
export const getSigningCertValidityReport = () => api.get('/signing-certificates/validity').then((r) => r.data);
export const runSigningCertValidityCheckNow = () => api.post('/signing-certificates/validity/check').then((r) => r.data);
export const createSigningCertRenewalRequest = (id, req) => api.post(`/signing-certificates/${id}/renew-request`, req ?? { reuseExistingKey: true }).then((r) => r.data);
// ---- User Management (ADMIN only) ----
export const getUsers = () => api.get('/users').then((r) => r.data);
export const getRoles = () => api.get('/roles').then((r) => r.data);
export const createUser = (req) => api.post('/users', req).then((r) => r.data);
export const updateUser = (id, req) => api.put(`/users/${id}`, req).then((r) => r.data);
export const resetUserPassword = (id, newPassword) => api.post(`/users/${id}/reset-password`, newPassword ? { newPassword } : {}).then((r) => r.data);
export const deleteUser = (id) => api.delete(`/users/${id}`).then((r) => r.data);
export const getUserCertificates = (userId) => api.get(`/users/${userId}/certificates`).then((r) => r.data);
export const assignUserCertificate = (userId, certificatePem) => api.post(`/users/${userId}/certificates`, { certificatePem }).then((r) => r.data);
export const removeUserCertificate = (userId, certId) => api.delete(`/users/${userId}/certificates/${certId}`).then((r) => r.data);
// ---- Cryptographic Providers & HSM Devices (DB + Pattern 2 Runtime Activation) ----
export const getCryptoProviders = () => api.get('/crypto-providers').then((r) => r.data);
export const discoverCryptoProviderSlots = (providerId) => api.get(`/crypto-providers/${providerId}/slots`).then((r) => r.data);
export const initializeCryptoProviderToken = (providerId, req) => api.post(`/crypto-providers/${providerId}/tokens/initialize`, req).then((r) => r.data);
export const getAllowedLibraryDirs = () => api.get('/crypto-providers/allowed-dirs').then((r) => r.data);
export const createCryptoProvider = (req) => api.post('/crypto-providers', req).then((r) => r.data);
export const updateCryptoProvider = (id, req) => api.put(`/crypto-providers/${id}`, req).then((r) => r.data);
export const deleteCryptoProvider = (id) => api.delete(`/crypto-providers/${id}`).then((r) => r.data);
export const getCryptoDevices = () => api.get('/crypto-devices').then((r) => r.data);
export const createCryptoDevice = (req) => api.post('/crypto-devices', req).then((r) => r.data);
export const updateCryptoDevice = (id, req) => api.put(`/crypto-devices/${id}`, req).then((r) => r.data);
export const deleteCryptoDevice = (id) => api.delete(`/crypto-devices/${id}`).then((r) => r.data);
export const activateCryptoDevice = (deviceId, pin) => api.post(`/crypto-devices/${encodeURIComponent(deviceId)}/activate`, { pin }).then((r) => r.data);
export const deactivateCryptoDevice = (deviceId) => api.post(`/crypto-devices/${encodeURIComponent(deviceId)}/deactivate`).then((r) => r.data);
export const syncCryptoDeviceKeys = (deviceId) => api.post(`/crypto-devices/${encodeURIComponent(deviceId)}/sync-keys`).then((r) => r.data);
export const getOcspReadiness = () => axios.get('/ocsp/health', { validateStatus: (s) => s === 200 || s === 503 }).then((r) => ({ httpStatus: r.status, ...r.data }));
// ---- First-Class OCSP Signers (HSM Tokens + Key + CSR + Cert) ----
export const getSigners = () => api.get('/signers').then((r) => r.data);
export const getOcspKeys = () => api.get('/signers/keys').then((r) => r.data);
export const getSignerById = (id) => api.get(`/signers/${id}`).then((r) => r.data);
export const createSigner = (req) => api.post('/signers', req).then((r) => r.data);
export const updateSigner = (id, req) => api.put(`/signers/${id}`, req).then((r) => r.data);
export const deleteSigner = (id) => api.delete(`/signers/${id}`).then((r) => r.data);
export const generateSignerCsr = (id, req) => api.post(`/signers/${id}/csr`, req ?? {}).then((r) => r.data);
export const getSignerCsr = (id, generateIfMissing = false) => api.get(`/signers/${id}/csr`, { params: { generateIfMissing } }).then((r) => r.data);
export const getSignerCertificate = (id) => api.get(`/signers/${id}/cert`).then((r) => r.data);
export const importSignerCertificate = (id, req) => api.post(`/signers/${id}/cert`, req).then((r) => r.data);
export const activateSigner = (id) => api.put(`/signers/${id}/activate`).then((r) => r.data);
export const deactivateSigner = (id) => api.put(`/signers/${id}/deactivate`).then((r) => r.data);
// ---- Trusted CAs (Hot-reloaded mTLS Truststore) ----
export const getTrustedCas = () => api.get('/trusted-cas').then((r) => r.data);
export const importTrustedCa = (alias, certificatePem) => api.post('/trusted-cas', { alias, certificatePem }).then((r) => r.data);
export const toggleTrustedCa = (id, enabled) => api.put(`/trusted-cas/${id}/enabled`, { enabled }).then((r) => r.data);
export const deleteTrustedCa = (id) => api.delete(`/trusted-cas/${id}`).then((r) => r.data);
