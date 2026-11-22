package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** RabbitMQ topology names ({@code ocsp.rabbitmq.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.rabbitmq")
public class OcspRabbitMqProperties {

    private String exchange = "incert.certificate.status";
    private String queue = "ocsp.certificate.status";
    private String routingKey = "incert.certificate.status.v1";
    private String deadLetterExchange = "incert.certificate.status.dlx";
    private String deadLetterQueue = "ocsp.certificate.status.dlq";
    private String reconciliationManifestQueue = "ocsp.reconciliation.manifest";
    private String reconciliationManifestRoutingKey = "incert.reconciliation.manifest.v1";
    private String reconciliationRequestQueue = "kms.reconciliation.request";
    private String reconciliationRequestRoutingKey = "incert.reconciliation.request.v1";
}

