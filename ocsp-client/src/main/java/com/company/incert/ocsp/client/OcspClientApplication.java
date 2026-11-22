package com.company.incert.ocsp.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.security.Security;

@SpringBootApplication
@ConfigurationPropertiesScan("com.company.incert.ocsp.client.config")
public class OcspClientApplication {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(OcspClientApplication.class, args);
    }
}

