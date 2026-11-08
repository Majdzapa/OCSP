package com.company.incert.ocsp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class OcspApplication {
    public static void main(String[] args) {
        SpringApplication.run(OcspApplication.class, args);
    }
}

