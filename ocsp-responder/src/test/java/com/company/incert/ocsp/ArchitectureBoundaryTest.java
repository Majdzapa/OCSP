package com.company.incert.ocsp;

import com.company.incert.ocsp.auth.controller.AuthController;
import com.company.incert.ocsp.auth.repository.UserRepository;
import com.company.incert.ocsp.auth.security.AuthenticationService;
import com.company.incert.ocsp.status.service.CertificateStatusService;
import com.company.incert.ocsp.auth.service.KeycloakAdminClient;
import com.company.incert.ocsp.responder.service.OcspResponderService;
import com.company.incert.ocsp.rabbitmq.service.OutboxReconciliationService;
import com.company.incert.ocsp.signing.service.SigningCertificateService;
import com.company.incert.ocsp.signing.service.SigningCertificateValidityService;
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

