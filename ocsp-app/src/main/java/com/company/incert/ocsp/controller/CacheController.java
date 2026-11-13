package com.company.incert.ocsp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Cache management stub.
 * In this monolithic architecture, caching has been removed in favor of direct
 * DB lookups and fresh cryptographic signatures on every request.
 */
@RestController
@RequestMapping("/api/v1/admin/cache")
public class CacheController {

    @GetMapping
    public ResponseEntity<Map<String, Object>> getCacheEntries(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "25") int size) {
        return ResponseEntity.ok(Map.of(
            "content", List.of(),
            "totalElements", 0,
            "totalPages", 0,
            "number", page,
            "size", size,
            "message", "Caching disabled in monolithic architecture"
        ));
    }

    @DeleteMapping
    public ResponseEntity<?> evictAll() {
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{key}")
    public ResponseEntity<?> evict(@PathVariable("key") String key) {
        return ResponseEntity.noContent().build();
    }
}
