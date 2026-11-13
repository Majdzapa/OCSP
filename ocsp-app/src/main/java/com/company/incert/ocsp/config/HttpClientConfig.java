package com.company.incert.ocsp.config;

import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

/** Shared HTTP client settings for the OCSP client and the KMS reconciliation job. */
@Configuration
public class HttpClientConfig {

    @Bean
    public RestClientCustomizer timeoutsCustomizer() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(3_000);
        factory.setReadTimeout(5_000);
        return builder -> builder.requestFactory(factory);
    }
}

