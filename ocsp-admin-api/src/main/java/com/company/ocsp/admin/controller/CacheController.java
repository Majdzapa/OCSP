package com.company.ocsp.admin.controller;

import com.company.ocsp.admin.dto.CacheEntryDto;
import com.company.ocsp.admin.service.CacheManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for cache inspection and manual invalidation.
 *
 * <p>Manual invalidation requires the {@code ROLE_OCSP_ADMIN} authority
 * (stricter than read-only operator).
 *
 * <p>Base path: {@code /api/v1/admin/cache}
 */
@RestController
@RequestMapping("/api/v1/admin/cache")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('OCSP_OPERATOR', 'OCSP_ADMIN')")
public class CacheController {

    private final CacheManagementService cacheManagementService;

    /**
     * Lists all current L2 cache entries, paginated.
     */
    @GetMapping
    public ResponseEntity<Page<CacheEntryDto>> listEntries(Pageable pageable) {
        return ResponseEntity.ok(cacheManagementService.listEntries(pageable));
    }

    /**
     * Looks up a specific cache entry by its 40-char SHA-1 cache key.
     */
    @GetMapping("/{cacheKey}")
    public ResponseEntity<CacheEntryDto> findByCacheKey(@PathVariable String cacheKey) {
        return cacheManagementService.findByCacheKey(cacheKey)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Manually invalidates a cache entry.  Requires OCSP_ADMIN role.
     * The operator's identity is logged in the audit trail.
     */
    @DeleteMapping("/{cacheKey}")
    @PreAuthorize("hasRole('OCSP_ADMIN')")
    public ResponseEntity<Void> invalidate(
            @PathVariable String cacheKey,
            @AuthenticationPrincipal Jwt jwt) {
        String operatorId = jwt.getSubject();
        cacheManagementService.invalidate(cacheKey, operatorId);
        return ResponseEntity.noContent().build();
    }
}
