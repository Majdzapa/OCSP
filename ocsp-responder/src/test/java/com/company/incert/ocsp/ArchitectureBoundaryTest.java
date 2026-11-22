package com.company.incert.ocsp;

import com.company.incert.ocsp.controller.AuthController;
import com.company.incert.ocsp.repository.UserRepository;
import com.company.incert.ocsp.security.AuthenticationService;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.company.incert.ocsp.service.KeycloakAdminClient;
import com.company.incert.ocsp.service.OcspResponderService;
import com.company.incert.ocsp.service.OutboxReconciliationService;
import com.company.incert.ocsp.service.SigningCertificateService;
import com.company.incert.ocsp.service.SigningCertificateValidityService;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Enforces Modular Monolith separation: OCSP business services must never depend
 * on login, credential encoding, user persistence, or Keycloak admin components.
 */
class ArchitectureBoundaryTest {

    private static final Set<Class<?>> FORBIDDEN_AUTH_DEPENDENCIES = Set.of(
            AuthController.class,
            AuthenticationService.class,
            UserRepository.class,
            PasswordEncoder.class,
            KeycloakAdminClient.class
    );

    private static final List<Class<?>> BUSINESS_SERVICES = List.of(
            OcspResponderService.class,
            CertificateStatusService.class,
            SigningCertificateService.class,
            SigningCertificateValidityService.class,
            OutboxReconciliationService.class
    );

    @Test
    void businessServicesMustNotDependOnLoginOrAuthComponents() {
        for (Class<?> businessClass : BUSINESS_SERVICES) {
            for (Field field : businessClass.getDeclaredFields()) {
                assertThat(FORBIDDEN_AUTH_DEPENDENCIES)
                        .as("Business service %s must not depend on auth type %s",
                                businessClass.getSimpleName(), field.getType().getSimpleName())
                        .doesNotContain(field.getType());
            }
        }
    }
}

