package lu.incert.ocsp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan("lu.incert.ocsp")
public class OcspResponderApplication {
    public static void main(String[] args) {
        SpringApplication.run(OcspResponderApplication.class, args);
    }
}
