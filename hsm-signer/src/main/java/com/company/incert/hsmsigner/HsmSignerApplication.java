package com.company.incert.hsmsigner;

import com.company.incert.hsmsigner.config.HsmSignerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(HsmSignerProperties.class)
public class HsmSignerApplication {

    public static void main(String[] args) {
        SpringApplication.run(HsmSignerApplication.class, args);
    }
}

