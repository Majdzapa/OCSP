package com.company.incert.ocsp.admin.adapter.in;

import com.company.incert.ocsp.admin.application.port.in.GetRevocationFeedUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class RevocationFeedController {

    private final GetRevocationFeedUseCase getRevocationFeedUseCase;

    @GetMapping({"/revocations", "/revocation-feed"})
    public ResponseEntity<Map<String, Object>> getRevoked(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "50") int size) {
        List<Map<String, String>> content = getRevocationFeedUseCase.getRevoked(page, size);
        return ResponseEntity.ok(Map.of(
            "content", content,
            "totalElements", content.size(),
            "totalPages", 1,
            "number", page,
            "size", size
        ));
    }
}
