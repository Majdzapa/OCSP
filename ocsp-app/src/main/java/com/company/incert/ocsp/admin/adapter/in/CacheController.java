package com.company.incert.ocsp.admin.adapter.in;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HexFormat;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/cache")
@RequiredArgsConstructor
public class CacheController {

    private final CacheEvictor cacheEvictor;

    @GetMapping
    public ResponseEntity<Map<String, Object>> getCacheEntries(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "25") int size) {
        return ResponseEntity.ok(Map.of(
            "content", java.util.List.of(),
            "totalElements", 0,
            "totalPages", 0,
            "number", page,
            "size", size
        ));
    }

    @DeleteMapping
    public ResponseEntity<Map<String, String>> evictAll() {
        cacheEvictor.evictAll();
        return ResponseEntity.ok(Map.of("evicted", "all"));
    }

    /** Evict by composite key: issuerNameHashHex:issuerKeyHashHex:serialHex */
    @DeleteMapping("/{compositeKey}")
    public ResponseEntity<?> evict(@PathVariable("compositeKey") String compositeKey) {
        String[] parts = compositeKey.split(":");
        if (parts.length != 3) {
            return ResponseEntity.badRequest().body(Map.of("error", "Key format: nameHash:keyHash:serial (hex)"));
        }
        HexFormat hex = HexFormat.of();
        CertId certId = new CertId(hex.parseHex(parts[0]), hex.parseHex(parts[1]), hex.parseHex(parts[2]));
        cacheEvictor.evict(certId);
        return ResponseEntity.ok(Map.of("evicted", compositeKey));
    }
}
