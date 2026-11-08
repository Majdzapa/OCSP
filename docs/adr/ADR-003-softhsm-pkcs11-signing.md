# ADR-003: SoftHSM2 (PKCS#11) for OCSP Response Signing

## Status
Accepted

## Context
In the previous architecture, the OCSP responder sent to-be-signed (TBS) bytes to an external KMS HTTP API over mTLS for each cache miss (`KMS_SIGNING_API_URL`, `KMS_OCSP_KEY_REF`).
This approach caused:
1. Significant latency overhead: every signing operation required an HTTP roundtrip.
2. Network dependency on the KMS on the critical OCSP request path.
3. KMS service was overloaded with high-frequency OCSP signing requests.

## Decision
Adopt SoftHSM2 accessed via standard PKCS#11 (`SunPKCS11` provider) directly within the OCSP responder container.
1. The signing private key is generated inside the HSM token with `CKA_EXTRACTABLE=false` and never leaves the HSM security boundary.
2. The KMS issues a delegated OCSP signing certificate (`id-kp-OCSPSigning`, `id-pkix-ocsp-nocheck`) that is imported into the token.
3. Signing operations execute locally inside the HSM token via PKCS#11 C API, avoiding network hops.
4. Signing cert rotation is supported at runtime without application restarts.

## Consequences
- High-performance, low-latency signing on the OCSP evaluation path (sub-millisecond cryptographic operations).
- Strict hardware security boundary: private keys are non-extractable.
- Eliminates `KMS_SIGNING_API_URL` and `KMS_OCSP_KEY_REF` network dependencies.
- A test-only `SoftwareKeyOcspSigner` adapter is retained strictly for isolated unit testing.

