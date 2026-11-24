package lu.incert.ocsp.signing;


import lu.incert.ocsp.signing.controller.SigningCertificateController;
import lu.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import lu.incert.ocsp.signing.dto.SigningCertificateDto;
import lu.incert.ocsp.signing.service.SigningCertificateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SigningCertificateControllerTest {

    private SigningCertificateService service;
    private SigningCertificateController controller;

    @BeforeEach
    void setUp() {
        service = mock(SigningCertificateService.class);
        controller = new SigningCertificateController(service);
    }

    @Test
    void listAll_returnsListFromService() {
        SigningCertificateDto dto = new SigningCertificateDto(
                1L, "alias1", "key1", "CN=Subject", "CN=Issuer", "01",
                Instant.now(), Instant.now().plusSeconds(86400),
                "SHA256withRSA", true, 1L, false, Instant.now(), Instant.now(), "PEM"
        );
        when(service.listAll()).thenReturn(List.of(dto));

        ResponseEntity<List<SigningCertificateDto>> response = controller.listAll();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).alias()).isEqualTo("alias1");
    }

    @Test
    void getActive_whenPresent_returns200() {
        SigningCertificateDto dto = new SigningCertificateDto(
                2L, "active-cert", "key2", "CN=Active", "CN=CA", "02",
                Instant.now(), Instant.now().plusSeconds(86400),
                "SHA256withRSA", true, 1L, false, Instant.now(), Instant.now(), "PEM"
        );
        when(service.getActiveCertificate()).thenReturn(Optional.of(dto));

        ResponseEntity<SigningCertificateDto> response = controller.getActive();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().alias()).isEqualTo("active-cert");
    }

    @Test
    void getActive_whenNone_returns404() {
        when(service.getActiveCertificate()).thenReturn(Optional.empty());

        ResponseEntity<SigningCertificateDto> response = controller.getActive();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void activate_callsServiceAndReturnsDto() {
        SigningCertificateDto dto = new SigningCertificateDto(
                3L, "activated-cert", "key3", "CN=Active", "CN=CA", "03",
                Instant.now(), Instant.now().plusSeconds(86400),
                "SHA256withRSA", true, 1L, false, Instant.now(), Instant.now(), "PEM"
        );
        when(service.activate(3L)).thenReturn(dto);

        ResponseEntity<?> response = controller.activate(3L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(dto);
        verify(service, times(1)).activate(3L);
    }

    @Test
    void addCertificate_callsServiceWithRequest() {
        AddSigningCertificateRequest request = new AddSigningCertificateRequest(
                "new-alias", "key-label", "CERT-PEM", true
        );
        SigningCertificateDto dto = new SigningCertificateDto(
                4L, "new-alias", "key-label", "CN=New", "CN=CA", "04",
                Instant.now(), Instant.now().plusSeconds(86400),
                "SHA256withRSA", true, 1L, false, Instant.now(), Instant.now(), "CERT-PEM"
        );
        when(service.addCertificate(request)).thenReturn(dto);

        var adminAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
        ResponseEntity<?> response = controller.addCertificate(request, adminAuth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isEqualTo(dto);
        verify(service, times(1)).addCertificate(request);
    }

    @Test
    void addCertificate_agentCannotActivateImmediately() {
        AddSigningCertificateRequest request = new AddSigningCertificateRequest(
                "agent-alias", "key-label", "CERT-PEM", true
        );
        var agentAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "agent", null, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_AGENT")));

        ResponseEntity<?> response = controller.addCertificate(request, agentAuth);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        verify(service, times(0)).addCertificate(request);
    }

    @Test
    void delete_callsServiceAndReturns204() {
        doNothing().when(service).delete(5L);

        ResponseEntity<?> response = controller.delete(5L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(service, times(1)).delete(5L);
    }
}
