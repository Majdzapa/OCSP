package lu.incert.ocsp.shared.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

import java.io.IOException;

/**
 * Spring Boot idiomatic SPA resource configuration for the embedded {@code ocsp-console} React UI
 * mounted strictly under {@code /console/**}.
 * <p>
 * Any client-side React Router path under {@code /console/**} automatically falls back to
 * {@code classpath:/static/console/index.html}, eliminating manual route duplication while keeping
 * {@code /ocsp}, {@code /api/**}, {@code /docs/**}, and {@code /actuator/**} completely isolated.
 */
@Configuration
public class SpaWebMvcConfig implements WebMvcConfigurer {

    public static final String CONSOLE_INDEX = "/static/console/index.html";

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/console/**")
                .addResourceLocations("classpath:/static/console/")
                .resourceChain(true)
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String resourcePath, Resource location) throws IOException {
                        Resource requested = location.createRelative(resourcePath);
                        if (requested.exists() && requested.isReadable()) {
                            return requested;
                        }
                        // Never return HTML for missing static assets (JS/CSS/maps/images)
                        if (resourcePath.startsWith("assets/") || resourcePath.contains(".")) {
                            return null;
                        }
                        Resource index = new ClassPathResource(CONSOLE_INDEX);
                        return index.exists() ? index : null;
                    }
                });
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/", "/console/");
        registry.addRedirectViewController("/console", "/console/");
        registry.addViewController("/console/").setViewName("forward:/console/index.html");
        registry.addRedirectViewController("/docs", "/docs/ocsp/5.0/index.html");
        registry.addRedirectViewController("/docs/", "/docs/ocsp/5.0/index.html");
    }
}

