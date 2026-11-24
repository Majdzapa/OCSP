package lu.incert.ocsp.responder;


import lu.incert.ocsp.responder.controller.OcspResponderController;
import lu.incert.ocsp.responder.service.OcspResponderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class OcspResponderControllerTest {

    private OcspResponderService responderService;
    private OcspResponderController controller;

    @BeforeEach
    void setUp() {
        responderService = mock(OcspResponderService.class);
        controller = new OcspResponderController(responderService);
    }

    @Test
    void handlePost_validRequest_returnsOcspResponse() {
        byte[] requestDer = new byte[]{0x30, 0x10, 0x02, 0x01, 0x01};
        byte[] responseDer = new byte[]{0x30, 0x20, 0x0a, 0x01, 0x00};

        when(responderService.handle(requestDer)).thenReturn(responseDer);

        ResponseEntity<byte[]> response = controller.handlePost(requestDer);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.parseMediaType("application/ocsp-response"));
        assertThat(response.getBody()).isEqualTo(responseDer);
    }

    @Test
    void handleGet_validBase64Request_decodesAndReturnsResponse() {
        byte[] requestDer = new byte[]{0x30, 0x15, 0x02, 0x01, 0x02};
        byte[] responseDer = new byte[]{0x30, 0x25, 0x0a, 0x01, 0x00};
        String base64Url = Base64.getUrlEncoder().encodeToString(requestDer);

        when(responderService.handle(requestDer)).thenReturn(responseDer);

        ResponseEntity<byte[]> response = controller.handleGet(base64Url);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.parseMediaType("application/ocsp-response"));
        assertThat(response.getBody()).isEqualTo(responseDer);
    }

    @Test
    void handleGet_invalidBase64_returns400BadRequest() {
        ResponseEntity<byte[]> response = controller.handleGet("not-valid-base-64-%%%");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(responderService, never()).handle(any());
    }

    @Test
    void handlePost_emptyServiceResponse_returns500() {
        byte[] requestDer = new byte[]{0x30, 0x05};
        when(responderService.handle(requestDer)).thenReturn(new byte[0]);

        ResponseEntity<byte[]> response = controller.handlePost(requestDer);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void checkOcspReadiness_whenReady_returns200Ok() {
        var readyStatus = new OcspResponderService.OcspReadinessStatus(
                true, "READY", "ocsp-node-1", "softhsm-primary", "ocsp-signing-key", "ACTIVE", 180, "Ready");
        when(responderService.checkReadiness()).thenReturn(readyStatus);

        var response = controller.checkOcspReadiness();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst("X-OCSP-Node")).isEqualTo("ocsp-node-1");
        assertThat(response.getHeaders().getFirst("X-OCSP-Ready")).isEqualTo("true");
        assertThat(response.getBody()).isEqualTo(readyStatus);
    }

    @Test
    void checkOcspReadiness_whenLocked_returns503ServiceUnavailable() {
        var lockedStatus = new OcspResponderService.OcspReadinessStatus(
                false, "HSM_DEVICE_LOCKED", "ocsp-node-3", "softhsm-primary", "ocsp-signing-key", "LOCKED", 180, "Locked");
        when(responderService.checkReadiness()).thenReturn(lockedStatus);

        var response = controller.checkOcspReadiness();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().getFirst("X-OCSP-Node")).isEqualTo("ocsp-node-3");
        assertThat(response.getHeaders().getFirst("X-OCSP-Ready")).isEqualTo("false");
        assertThat(response.getBody()).isEqualTo(lockedStatus);
    }
}

