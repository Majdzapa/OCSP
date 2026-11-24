package lu.incert.ocsp.client.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
@RequiredArgsConstructor
public class HttpClientConfig {

    private final OcspClientProperties properties;

    @Bean
    public RestClient.Builder restClientBuilder() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        if (properties.getConnectTimeout() != null) {
            factory.setConnectTimeout(properties.getConnectTimeout());
        }
        if (properties.getReadTimeout() != null) {
            factory.setReadTimeout(properties.getReadTimeout());
        }
        return RestClient.builder().requestFactory(factory);
    }
}
