package com.company.ocsp.admin.controller;

import com.company.ocsp.admin.dto.RevocationEventDto;
import com.company.ocsp.admin.service.RevocationActivityService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for the revocation activity feed shown on the React console.
 *
 * <p>Base path: {@code /api/v1/admin/revocations}
 */
@RestController
@RequestMapping("/api/v1/admin/revocations")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('OCSP_OPERATOR', 'OCSP_ADMIN')")
public class RevocationActivityController {

    private final RevocationActivityService revocationActivityService;

    /**
     * Returns a paginated, time-ordered list of recent revocation and issuance events.
     */
    @GetMapping
    public ResponseEntity<Page<RevocationEventDto>> list(Pageable pageable) {
        return ResponseEntity.ok(revocationActivityService.listRecent(pageable));
    }
}
