package lu.incert.ocsp.shared.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Forwards React Router SPA client-side paths to {@code /index.html} so the
 * embedded {@code ocsp-console} UI is served directly by {@code ocsp-responder}.
 */
@Controller
public class SpaForwardingController {

    @GetMapping({
        "/login",
        "/ocsp-client",
        "/dashboard",
        "/inbox",
        "/revocations",
        "/signing-cert",
        "/signing-certificates",
        "/hsm-devices",
        "/signing-validity",
        "/cert-checker",
        "/trusted-cas",
        "/users",
        "/audit"
    })
    public String forwardSpaRoutes() {
        return "forward:/index.html";
    }

    @GetMapping({"/docs", "/docs/"})
    public String redirectDocsRoot() {
        return "redirect:/docs/ocsp/5.0/index.html";
    }
}

