package com.company.incert.kms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class KmsSimulatorApplication {
    public static void main(String[] args) {
        SpringApplication.run(KmsSimulatorApplication.class, args);
    }
}
