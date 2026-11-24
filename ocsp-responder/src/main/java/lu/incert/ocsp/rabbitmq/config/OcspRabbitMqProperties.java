package lu.incert.ocsp.rabbitmq.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** RabbitMQ topology names ({@code ocsp.rabbitmq.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.rabbitmq")
public class OcspRabbitMqProperties {

    private String exchange;
    private String queue;
    private String routingKey;
    private String deadLetterExchange;
    private String deadLetterQueue;
    private String reconciliationManifestQueue;
    private String reconciliationManifestRoutingKey;
    private String reconciliationRequestQueue;
    private String reconciliationRequestRoutingKey;
}
