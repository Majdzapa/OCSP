package lu.incert.ocsp.shared.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringJUnitWebConfig(SpaWebMvcConfigTest.TestMvcConfig.class)
class SpaWebMvcConfigTest {

    @Configuration
    @EnableWebMvc
    @Import(SpaWebMvcConfig.class)
    static class TestMvcConfig {}

    private MockMvc mockMvc;

    @BeforeEach
    void setUp(WebApplicationContext wac) {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();
    }

    @Test
    void redirectsRootConsoleAndDocsEntryPoints() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/console/"));

        mockMvc.perform(get("/console"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/console/"));

        mockMvc.perform(get("/docs"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/docs/ocsp/5.0/index.html"));

        mockMvc.perform(get("/docs/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/docs/ocsp/5.0/index.html"));
    }

    @Test
    void fallsBackArbitraryConsoleSpaRoutesToIndexHtmlWithoutMaskingMissingAssets() throws Exception {
        mockMvc.perform(get("/console/hsm-devices"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/console/assets/")));

        mockMvc.perform(get("/console/future-feature/sub-page"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/console/assets/")));

        mockMvc.perform(get("/console/assets/does-not-exist.js"))
                .andExpect(status().isNotFound());
    }
}
