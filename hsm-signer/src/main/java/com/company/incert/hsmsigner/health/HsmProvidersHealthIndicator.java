package com.company.incert.hsmsigner.health;

import com.company.incert.pkcs11j.provider.Pkcs11Provider;
import com.company.incert.pkcs11j.provider.PkcsProviders;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring Boot 4 {@link HealthIndicator} reporting live token status for all PKCS11J devices.
 */
@Component("pkcsProvidersHealthIndicator")
@RequiredArgsConstructor
public class HsmProvidersHealthIndicator implements HealthIndicator {

    private final PkcsProviders pkcsProviders;

    @Override
    public Health health() {
        List<Pkcs11Provider> providers = pkcsProviders.listProviders();
        if (providers.isEmpty()) {
            return Health.down().withDetail("reason", "No PKCS11J providers registered").build();
        }
        boolean allUp = true;
        Map<String, Object> details = new LinkedHashMap<>();
        for (Pkcs11Provider provider : providers) {
            try {
                details.put(provider.getProviderId(), provider.healthCheck());
            } catch (Exception e) {
                allUp = false;
                details.put(provider.getProviderId(), "DOWN: " + e.getMessage());
            }
        }
        Health.Builder builder = allUp ? Health.up() : Health.down();
        details.forEach(builder::withDetail);
        return builder.build();
    }
}

