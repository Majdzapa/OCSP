package com.company.incert.ocsp.admin.adapter.in;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
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
    private final OcspResponseCachePort responseCachePort;

    @GetMapping
    public ResponseEntity<Map<String, Object>> getCacheEntries(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "25") int size) {
        var list = responseCachePort.getCacheEntries(page, size);
        long count = responseCachePort.count();
        int totalPages = count == 0 ? 0 : (int) Math.ceil((double) count / size);
        return ResponseEntity.ok(Map.of(
            "content", list,
            "totalElements", count,
            "totalPages", totalPages,
            "number", page,
            "size", size
        ));
    }

    @DeleteMapping
    public ResponseEntity<?> evictAll() {
        cacheEvictor.evictAll();
        return ResponseEntity.noContent().build();
    }

    /** Evict by 40-char SHA-1 cacheKey OR composite key: nameHash:keyHash:serial */
    @DeleteMapping("/{key}")
    public ResponseEntity<?> evict(@PathVariable("key") String key) {
        if (key.length() == 40) {
            responseCachePort.evict(key);
            return ResponseEntity.noContent().build();
        }
        String[] parts = key.split(":");
        if (parts.length == 3) {
            HexFormat hex = HexFormat.of();
            CertId certId = new CertId(hex.parseHex(parts[0]), hex.parseHex(parts[1]), hex.parseHex(parts[2]));
            cacheEvictor.evict(certId);
            return ResponseEntity.noContent().build();
        }
        responseCachePort.evict(key);
        return ResponseEntity.noContent().build();
    }
}

