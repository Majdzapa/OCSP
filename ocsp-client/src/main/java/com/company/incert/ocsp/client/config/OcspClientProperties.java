package com.company.incert.ocsp.client.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Settings of the standalone OCSP client ({@code ocsp.client.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.client")
public class OcspClientProperties {

    /** Responder URL used when a request does not specify one. */
    private String defaultResponderUrl = "http://localhost:8080/ocsp";

    /** Optional directory holding a trusted CA certificate (intermediate-ca-cert.pem, ...). */
    private String pkiDir = "./data/pki";
}

