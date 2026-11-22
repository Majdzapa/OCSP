package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.KeycloakProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.*;

/**
 * Least-privilege Keycloak Admin REST API client authenticated via {@code client_credentials}
 * using {@code keycloak.service-account.*} ({@code view-users}, {@code manage-users}).
 * Never accesses Keycloak's database directly.
 */
@Slf4j
@Component
public class KeycloakAdminClient {

    public record KeycloakUserRepresentation(
        String id,
        String username,
        String email,
        boolean emailVerified,
        String firstName,
        String lastName,
        boolean enabled
    ) {
        public String fullName() {
            String f = firstName != null ? firstName.trim() : "";
            String l = lastName != null ? lastName.trim() : "";
            String joined = (f + " " + l).trim();
            return joined.isEmpty() ? null : joined;
        }
    }

    private final KeycloakProperties keycloakProperties;
    private final RestClient restClient;

    public KeycloakAdminClient(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
        this.restClient = RestClient.builder().build();
    }

    @SuppressWarnings("unchecked")
    public String fetchServiceAccountToken() {
        String tokenUrl = keycloakProperties.getAuthServerUrl()
                + "/realms/" + keycloakProperties.getRealm()
                + "/protocol/openid-connect/token";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", keycloakProperties.getServiceAccount().getClientId());
        form.add("client_secret", keycloakProperties.getServiceAccount().getClientSecret());

        Map<String, Object> response = restClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        if (response == null || !response.containsKey("access_token")) {
            throw new IllegalStateException("Keycloak service account token endpoint returned no access_token");
        }
        return response.get("access_token").toString();
    }

    public String createUser(String username, String email, String fullName, boolean enabled) {
        String token = fetchServiceAccountToken();
        String[] parts = splitName(fullName);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        if (email != null && !email.isBlank()) {
            body.put("email", email);
        }
        if (parts[0] != null) body.put("firstName", parts[0]);
        if (parts[1] != null) body.put("lastName", parts[1]);
        body.put("enabled", enabled);

        var entity = restClient.post()
                .uri(adminUsersUrl())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .toBodilessEntity();

        URI location = entity.getHeaders().getLocation();
        if (location != null) {
            String path = location.getPath();
            int idx = path.lastIndexOf('/');
            if (idx >= 0 && idx < path.length() - 1) {
                return path.substring(idx + 1);
            }
        }
        return findUserByUsername(username)
                .map(KeycloakUserRepresentation::id)
                .orElseThrow(() -> new IllegalStateException("Created user in Keycloak but could not resolve external_id"));
    }

    public void updateUser(String externalId, String email, String fullName, Boolean enabled) {
        String token = fetchServiceAccountToken();
        Map<String, Object> body = new LinkedHashMap<>();
        if (email != null) body.put("email", email);
        if (fullName != null) {
            String[] parts = splitName(fullName);
            body.put("firstName", parts[0] != null ? parts[0] : "");
            body.put("lastName", parts[1] != null ? parts[1] : "");
        }
        if (enabled != null) body.put("enabled", enabled);

        restClient.put()
                .uri(adminUsersUrl() + "/" + externalId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .toBodilessEntity();
    }

    public void deleteUser(String externalId) {
        String token = fetchServiceAccountToken();
        restClient.delete()
                .uri(adminUsersUrl() + "/" + externalId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity();
    }

    public void sendResetPasswordEmail(String externalId) {
        String token = fetchServiceAccountToken();
        restClient.put()
                .uri(adminUsersUrl() + "/" + externalId + "/execute-actions-email")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(List.of("UPDATE_PASSWORD"))
                .retrieve()
                .toBodilessEntity();
    }

    @SuppressWarnings("unchecked")
    public Optional<KeycloakUserRepresentation> findUserByUsername(String username) {
        String token = fetchServiceAccountToken();
        List<Map<String, Object>> list = restClient.get()
                .uri(adminUsersUrl() + "?username=" + username + "&exact=true")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .body(List.class);
        if (list == null || list.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(toRepresentation(list.get(0)));
    }

    @SuppressWarnings("unchecked")
    public List<KeycloakUserRepresentation> listAllUsers() {
        String token = fetchServiceAccountToken();
        List<KeycloakUserRepresentation> all = new ArrayList<>();
        int first = 0;
        int max = 100;
        while (true) {
            List<Map<String, Object>> page = restClient.get()
                    .uri(adminUsersUrl() + "?first=" + first + "&max=" + max)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .body(List.class);
            if (page == null || page.isEmpty()) {
                break;
            }
            for (Map<String, Object> item : page) {
                all.add(toRepresentation(item));
            }
            if (page.size() < max) {
                break;
            }
            first += max;
        }
        return all;
    }

    private String adminUsersUrl() {
        return keycloakProperties.getAuthServerUrl() + "/admin/realms/" + keycloakProperties.getRealm() + "/users";
    }

    private static KeycloakUserRepresentation toRepresentation(Map<String, Object> map) {
        return new KeycloakUserRepresentation(
                Objects.toString(map.get("id"), null),
                Objects.toString(map.get("username"), null),
                map.get("email") != null ? map.get("email").toString() : null,
                Boolean.TRUE.equals(map.get("emailVerified")),
                map.get("firstName") != null ? map.get("firstName").toString() : null,
                map.get("lastName") != null ? map.get("lastName").toString() : null,
                !Boolean.FALSE.equals(map.get("enabled"))
        );
    }

    private static String[] splitName(String fullName) {
        if (fullName == null || fullName.isBlank()) {
            return new String[]{null, null};
        }
        String trimmed = fullName.trim();
        int space = trimmed.indexOf(' ');
        if (space < 0) {
            return new String[]{trimmed, ""};
        }
        return new String[]{trimmed.substring(0, space).trim(), trimmed.substring(space + 1).trim()};
    }
}

