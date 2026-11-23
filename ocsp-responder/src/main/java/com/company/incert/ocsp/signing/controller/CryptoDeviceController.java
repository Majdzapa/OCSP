package com.company.incert.ocsp.signing.controller;

import com.company.incert.ocsp.shared.config.OpenApiConfig;
import com.company.incert.ocsp.signing.dto.ActivateCryptoDeviceRequest;
import com.company.incert.ocsp.signing.dto.CryptoDeviceDto;
import com.company.incert.ocsp.signing.dto.CryptoDeviceRequest;
import com.company.incert.ocsp.signing.dto.CryptoProviderDto;
import com.company.incert.ocsp.signing.dto.CryptoProviderRequest;
import com.company.incert.ocsp.signing.service.CryptoDeviceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * REST endpoints for managing DB-backed PKCS#11 drivers ({@code library_path} + {@code library_wrapper_path}),
 * HSM device slots, and Pattern 2 Runtime Activation ({@code unlock} / {@code lock}) without persisting PINs.
 */
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "Crypto Providers & HSM Devices", description = "DB-backed PKCS#11 drivers, wrappers, device slots, and runtime PIN unlock/lock")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class CryptoDeviceController {

    private final CryptoDeviceService cryptoDeviceService;

    // ---- Providers (library + libraryWrapper) ----

    @Operation(summary = "List configured cryptographic providers (vendor library + JNI wrapper)")
    @GetMapping("/crypto-providers")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_READ')")
    public ResponseEntity<List<CryptoProviderDto>> listProviders() {
        return ResponseEntity.ok(cryptoDeviceService.listProviders());
    }

    @Operation(summary = "List allowlisted host directories permitted for native PKCS#11/wrapper shared libraries")
    @GetMapping("/crypto-providers/allowed-dirs")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_READ')")
    public ResponseEntity<List<String>> allowedLibraryDirs() {
        return ResponseEntity.ok(cryptoDeviceService.listAllowedLibraryDirs());
    }

    @Operation(summary = "Discover live PKCS#11 slots and token metadata for a cryptographic provider (no PIN required)")
    @GetMapping("/crypto-providers/{id}/slots")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_READ')")
    public ResponseEntity<?> discoverProviderSlots(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(cryptoDeviceService.discoverProviderSlots(id));
        } catch (IllegalArgumentException e) {
            HttpStatus status = (e.getMessage() != null && e.getMessage().startsWith("Crypto provider not found"))
                    ? HttpStatus.NOT_FOUND
                    : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Create a new cryptographic provider")
    @PostMapping("/crypto-providers")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> createProvider(@Valid @RequestBody CryptoProviderRequest request) {
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(cryptoDeviceService.createProvider(request));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Update an existing cryptographic provider")
    @PutMapping("/crypto-providers/{id}")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> updateProvider(@PathVariable Long id, @Valid @RequestBody CryptoProviderRequest request) {
        try {
            return ResponseEntity.ok(cryptoDeviceService.updateProvider(id, request));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Delete a cryptographic provider (blocked if devices still reference it)")
    @DeleteMapping("/crypto-providers/{id}")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> deleteProvider(@PathVariable Long id) {
        try {
            cryptoDeviceService.deleteProvider(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ---- Devices & Pattern 2 Runtime Activation ----

    @Operation(summary = "List all DB crypto devices with live LOCKED/ACTIVE state and discovered keys")
    @GetMapping("/crypto-devices")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_READ')")
    public ResponseEntity<List<CryptoDeviceDto>> listDevices() {
        return ResponseEntity.ok(cryptoDeviceService.listDevices());
    }

    @Operation(summary = "Register a new HSM device / token slot in LOCKED state (zero PIN persisted)")
    @PostMapping("/crypto-devices")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> createDevice(@Valid @RequestBody CryptoDeviceRequest request) {
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(cryptoDeviceService.createDevice(request));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Update a DB crypto device configuration")
    @PutMapping("/crypto-devices/{id}")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> updateDevice(@PathVariable Long id, @Valid @RequestBody CryptoDeviceRequest request) {
        try {
            return ResponseEntity.ok(cryptoDeviceService.updateDevice(id, request));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Delete a crypto device (blocked if an active signing certificate uses it)")
    @DeleteMapping("/crypto-devices/{id}")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> deleteDevice(@PathVariable Long id) {
        try {
            cryptoDeviceService.deleteDevice(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Unlock / activate a crypto device at runtime using the transient HSM PIN (PIN wiped after C_Login)")
    @PostMapping("/crypto-devices/{deviceId}/activate")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> activateDevice(
            @PathVariable String deviceId,
            @Valid @RequestBody ActivateCryptoDeviceRequest request) {
        char[] pin = request.pin().toCharArray();
        try {
            return ResponseEntity.ok(cryptoDeviceService.activateDevice(deviceId, pin));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } finally {
            Arrays.fill(pin, '\0');
        }
    }

    @Operation(summary = "Lock / deactivate a crypto device (C_Logout & close PKCS#11 sessions)")
    @PostMapping("/crypto-devices/{deviceId}/deactivate")
    @PreAuthorize("hasPermission(null, 'CRYPTO_DEVICE_MANAGE')")
    public ResponseEntity<?> deactivateDevice(@PathVariable String deviceId) {
        try {
            return ResponseEntity.ok(cryptoDeviceService.deactivateDevice(deviceId));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}

