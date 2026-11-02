package com.company.ocsp.sync.client;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response from the KMS reconciliation endpoint.
 *
 * @param revokedCount Authoritative count of all certificates in REVOKED status
 *                     as known to the KMS.  Used by the reconciliation job to
 *                     detect drift between the local MariaDB and the KMS.
 */
public record ReconciliationResponse(
    @JsonProperty("revokedCount") long revokedCount
) {}
