package com.github.h3yow.authtokenrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.authtokenrotationjava.support.TestClockConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP-level tests for the rate-limit trust boundary. Uses the default
 * 5/1000ms sliding window (a dedicated context so counters are fresh) and a
 * controlled clock. Every scenario asserts that forged/invalid identities
 * consume <b>zero</b> quota of the real caller they pretend to be.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = {com.github.h3yow.authtokenrotationjava.Application.class, TestClockConfig.class})
class IdentityTrustHttpIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private com.github.h3yow.authtokenrotationjava.support.MutableClock clock;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @BeforeEach
    void slideWindow() {
        // Every test starts well past the previous window, and uses unique
        // caller names, so buckets never leak between scenarios.
        clock.advanceMillis(10_000);
    }

    @Test
    @DisplayName("forged access-token identity is 401 untrusted and never consumes the victim owner's quota")
    void forgedAccessIdentityConsumesNoOwnerQuota() {
        String victim = "trust-victim-1";
        String attacker = "trust-attacker-1";
        JsonNode login = login(victim, "victim").getBody();
        String accessToken = login.get("accessToken").asText();

        // Far more than the limit (5) of forged attempts: attacker header + the
        // victim's real credential. Every one must be rejected at the trust
        // boundary and billed nowhere.
        for (int i = 0; i < 12; i++) {
            ResponseEntity<JsonNode> forged = resource(attacker, accessToken);
            assertEquals(HttpStatus.UNAUTHORIZED, forged.getStatusCode());
            assertEquals("caller_identity_untrusted", forged.getBody().get("error").asText());
        }

        // The victim owner's AUTHENTICATED bucket is untouched: the next 5
        // legitimate requests all pass and only the 6th is throttled.
        for (int i = 1; i <= 5; i++) {
            assertEquals(HttpStatus.OK, resource(victim, accessToken).getStatusCode(),
                    "owner request " + i + " must pass: forged traffic consumed no quota");
        }
        ResponseEntity<JsonNode> sixth = resource(victim, accessToken);
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, sixth.getStatusCode());
        assertEquals("rate_limit_exceeded", sixth.getBody().get("error").asText());
        System.out.println("[identity-quota] forged access x12 -> owner victim still allowed=5 blocked6th=429");
    }

    @Test
    @DisplayName("forged refresh identity and unknown-token floods consume no real caller quota")
    void forgedRefreshAndUnknownTokenConsumeNoQuota() {
        String victim = "trust-victim-2";
        String attacker = "trust-attacker-2";
        JsonNode login = login(victim, "victim").getBody();
        String refreshToken = login.get("refreshToken").asText();
        String accessToken = login.get("accessToken").asText();

        for (int i = 0; i < 8; i++) {
            ResponseEntity<JsonNode> forgedRefresh = post("/api/auth/refresh", attacker,
                    Map.of("refreshToken", refreshToken));
            assertEquals(HttpStatus.UNAUTHORIZED, forgedRefresh.getStatusCode());
            assertEquals("caller_identity_untrusted", forgedRefresh.getBody().get("error").asText());

            ResponseEntity<JsonNode> unknown = resource(victim, "atk_this_token_does_not_exist");
            assertEquals(HttpStatus.UNAUTHORIZED, unknown.getStatusCode());
            assertEquals("caller_identity_untrusted", unknown.getBody().get("error").asText());
        }

        // Victim quota intact despite 16 untrusted requests claiming/bearing it.
        for (int i = 1; i <= 5; i++) {
            assertEquals(HttpStatus.OK, resource(victim, accessToken).getStatusCode());
        }
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, resource(victim, accessToken).getStatusCode());
        System.out.println("[identity-quota] forged refresh x8 + unknown token x8 -> owner allowed=5 then 429");
    }

    @Test
    @DisplayName("a request without any credential is untrusted and consumes no quota")
    void missingCredentialConsumesNoQuota() {
        String victim = "trust-victim-3";
        login(victim, "victim");
        for (int i = 0; i < 8; i++) {
            ResponseEntity<JsonNode> noCred = resource(victim, null);
            assertEquals(HttpStatus.UNAUTHORIZED, noCred.getStatusCode());
            assertEquals("caller_identity_untrusted", noCred.getBody().get("error").asText());
        }
        // Re-login to obtain a concrete token and prove the bucket is empty.
        JsonNode login2 = login(victim, "victim2").getBody();
        for (int i = 1; i <= 5; i++) {
            assertEquals(HttpStatus.OK, resource(victim, login2.get("accessToken").asText()).getStatusCode());
        }
        System.out.println("[identity-quota] missing-credential x8 consumed no owner quota");
    }

    @Test
    @DisplayName("issuance traffic is namespaced separately: saturating issuance never throttles an owner")
    void issuanceNamespaceIsIsolated() {
        String caller = "trust-issuance-4";
        JsonNode first = login(caller, "subject-1").getBody();
        // Saturate the caller's ISSUANCE bucket: 4 more pass (5 total), 6th blocked.
        for (int i = 2; i <= 5; i++) {
            assertEquals(HttpStatus.OK, login(caller, "subject-" + i).getStatusCode());
        }
        ResponseEntity<JsonNode> blocked = login(caller, "subject-6");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, blocked.getStatusCode());
        assertEquals("rate_limit_exceeded", blocked.getBody().get("error").asText());

        // At the SAME instant, the AUTHENTICATED bucket of the same named
        // caller starts empty: 5 protected requests pass, only the 6th is
        // throttled. Issuance saturation cannot touch it.
        for (int i = 1; i <= 5; i++) {
            ResponseEntity<JsonNode> ok = resource(caller, first.get("accessToken").asText());
            assertEquals(HttpStatus.OK, ok.getStatusCode(), "authenticated request " + i
                    + " uses a separate namespace from issuance");
        }
        ResponseEntity<JsonNode> sixth = resource(caller, first.get("accessToken").asText());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, sixth.getStatusCode());
        System.out.println("[identity-quota] issuance saturated=5/429; AUTHENTICATED independently allowed=5 then 429");
    }

    private ResponseEntity<JsonNode> login(String callerId, String subject) {
        return post("/api/auth/login", callerId, Map.of("subject", subject));
    }

    private ResponseEntity<JsonNode> post(String path, String callerId, Map<String, String> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Caller-Id", callerId);
        try {
            HttpEntity<String> entity = new HttpEntity<>(JSON.writeValueAsString(body), headers);
            ResponseEntity<String> response = restTemplate.postForEntity(url(path), entity, String.class);
            return toJson(response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseEntity<JsonNode> resource(String callerId, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Caller-Id", callerId);
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }
        try {
            ResponseEntity<String> response = restTemplate.exchange(url("/api/auth/resource"),
                    org.springframework.http.HttpMethod.POST, new HttpEntity<>("", headers), String.class);
            return toJson(response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseEntity<JsonNode> toJson(ResponseEntity<String> response) {
        JsonNode node = null;
        if (response.getBody() != null && !response.getBody().isBlank()) {
            try {
                node = JSON.readTree(response.getBody());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return new ResponseEntity<>(node, response.getStatusCode());
    }
}
