package lu.incert.ocsp.shared;

import lu.incert.ocsp.shared.config.ProductionSecretsValidator;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProductionSecretsValidatorTest {

    @Test
    void devProfileAllowsDefaultSecrets() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev");
        env.setProperty("spring.datasource.password", "changeme");
        assertThatCode(() -> new ProductionSecretsValidator(env).validate()).doesNotThrowAnyException();
    }

    @Test
    void prodProfileRejectsMissingOrDefaultSecrets() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        env.setProperty("app.auth.mode", "SELF_MANAGEMENT");
        env.setProperty("spring.datasource.password", "changeme");
        env.setProperty("spring.rabbitmq.password", "guest");
        env.setProperty("rabbitmq.tls.enabled", "false");
        env.setProperty("admin.password", "");

        assertThatThrownBy(() -> new ProductionSecretsValidator(env).validate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.password")
                .hasMessageContaining("spring.rabbitmq.password")
                .hasMessageContaining("admin.password");
    }

    @Test
    void prodProfilePassesWhenAllRequiredSecretsAreStrong() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        env.setProperty("app.auth.mode", "KEYCLOAK");
        env.setProperty("spring.datasource.password", "db-s3cr3t-v4l!");
        env.setProperty("spring.rabbitmq.password", "rmq-s3cr3t-v4l!");
        env.setProperty("rabbitmq.tls.enabled", "true");
        env.setProperty("spring.rabbitmq.ssl.key-store-password", "ks-s3cr3t-v4l!");
        env.setProperty("spring.rabbitmq.ssl.trust-store-password", "ts-s3cr3t-v4l!");

        assertThatCode(() -> new ProductionSecretsValidator(env).validate()).doesNotThrowAnyException();
    }
}

