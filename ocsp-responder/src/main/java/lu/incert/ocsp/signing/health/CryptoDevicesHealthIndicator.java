package lu.incert.ocsp.signing.health;

import lu.incert.ocsp.signing.port.DeviceActivationState;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.provider.PkcsProviders;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring Boot Actuator {@link HealthIndicator} reporting live status of in-process HSM devices.
 * <p>
 * Pattern 2 (Runtime Activation): {@code LOCKED} devices are a normal boot state waiting for admin PIN unlock
 * and therefore report {@code UP} (so containers start cleanly); only {@code ERROR} devices transition to {@code DOWN}.
 */
@Component("cryptoDevicesHealthIndicator")
@ConditionalOnBean(PkcsProviders.class)
@RequiredArgsConstructor
public class CryptoDevicesHealthIndicator implements HealthIndicator {

    private final PkcsProviders pkcsProviders;

    @Override
    public Health health() {
        List<ProviderDeviceInfo> devices = pkcsProviders.listProviders();
        long activeCount = 0;
        long lockedCount = 0;
        long errorCount = 0;

        Map<String, Object> deviceDetails = new LinkedHashMap<>();
        for (ProviderDeviceInfo info : devices) {
            String state = info.activationState();
            if (DeviceActivationState.ACTIVE.name().equals(state)) {
                activeCount++;
            } else if (DeviceActivationState.ERROR.name().equals(state)) {
                errorCount++;
            } else {
                lockedCount++;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("state", state);
            entry.put("type", info.providerType());
            entry.put("libraryPath", info.libraryPath());
            entry.put("libraryWrapperPath", info.libraryWrapperPath());
            entry.put("tokenLabel", info.tokenLabel());
            entry.put("slotId", info.slotId());
            entry.put("status", info.statusMessage());
            deviceDetails.put(info.providerId(), entry);
        }

        Health.Builder builder = errorCount > 0 ? Health.down() : Health.up();
        return builder
                .withDetail("mode", "RUNTIME_ACTIVATION")
                .withDetail("defaultProviderId", pkcsProviders.getDefaultProviderId())
                .withDetail("activeCount", activeCount)
                .withDetail("lockedCount", lockedCount)
                .withDetail("errorCount", errorCount)
                .withDetail("devices", deviceDetails)
                .build();
    }
}

