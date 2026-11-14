# ADR-009: Dynamic OCSP Signing Certificate Hot Rotation

## Status
Accepted

## Context
RFC 6960 OCSP responses must be signed either by the CA itself or by a designated OCSP signing certificate authorized by the CA (containing the `id-kp-OCSPSigning` Extended Key Usage).

In production, OCSP signing certificates have short lifespans or may need immediate revocation and rotation in the event of private key compromise. Re-deploying or restarting the responder service causes downtime and disrupts high-throughput TLS validations.

## Decision
1. **Database-Backed Certificate Registry**:
   - Implemented table `signing_certificates` (`V6__signing_certificates.sql`) tracking serial numbers, subject DN, issuer DN, validity periods, PKCS#11 key labels, and an `active` boolean flag.
2. **Single-Active Invariant**:
   - Enforced at both database and service levels: exactly one signing certificate can have `active = TRUE` at any given time. Activating a certificate automatically deactivates all others in an atomic transaction.
3. **Hot In-Memory Dynamic Re-Keying**:
   - `OcspSigner` implementations (`Pkcs11OcspSigner` and `SoftwareKeyOcspSigner`) expose `updateSigningCertificate(X509CertificateHolder, String keyLabel)`.
   - Admin rotation calls reload the active certificate in memory without interrupting active OCSP request processing or requiring a JVM restart.
4. **Admin UI & REST APIs**:
   - Admin endpoints `/api/v1/admin/signing-certificates` allow querying certificates, inspecting full X.509 PEM details, uploading new signing certificates, and triggering one-click activation.
   - Mantine v7 UI provides a dedicated "Signing Certificates" management page.

## Consequences
- **Positive**: Zero-downtime key rotation for OCSP response signing.
- **Positive**: Complete audit trail of past and current signing certificates.
- **Negative**: Administrators must ensure the corresponding private key is provisioned in the HSM token before activating a certificate.

