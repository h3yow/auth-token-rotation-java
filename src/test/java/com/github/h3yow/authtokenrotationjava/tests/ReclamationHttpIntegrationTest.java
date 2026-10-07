package com.github.h3yow.authtokenrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import com.github.h3yow.authtokenrotationjava.support.TestClockConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test for the operational purge endpoint. The endpoint lives
 * outside {@code /api/**}, so it needs no caller header and consumes no caller
 * rate-limit quota.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = {com.github.h3yow.authtokenrotationjava.Application.class, TestClockConfig.class})
@TestPropertySource(properties = {
        // A unique context marker so this class never shares the mutable store
        // with the other default-config HTTP tests; keeps "first sweep empty"
        // and per-category counts deterministic.
        "auth.reclamation.sweep-interval-millis=59999"
})
class ReclamationHttpIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private MutableClock clock;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    @DisplayName("POST /internal/maintenance/purge runs a sweep and reports per-category counts")
    void purgeEndpointReportsCategories() {
        // A first sweep on an empty store: well-formed report, zero removed.
        ResponseEntity<JsonNode> empty = restTemplate.postForEntity(url("/internal/maintenance/purge"),
                null, JsonNode.class);
        assertEquals(HttpStatus.OK, empty.getStatusCode());
        assertEquals(0, empty.getBody().get("totalRemoved").asInt());
        assertTrue(empty.getBody().has("removedByCategory"));
        assertTrue(empty.getBody().has("atMillis"));

        // Log a family out via the auth API so there is terminal state to reap.
        String caller = "reclaim-http-1";
        JsonNode login = login(caller, "zoe");
        String refreshToken = login.get("refreshToken").asText();
        restTemplate.postForEntity(url("/api/auth/logout"),
                jsonEntity(caller, "{\"refreshToken\":\"" + refreshToken + "\"}"), String.class);

        ResponseEntity<JsonNode> report = restTemplate.postForEntity(url("/internal/maintenance/purge"),
                null, JsonNode.class);
        assertEquals(HttpStatus.OK, report.getStatusCode());
        JsonNode categories = report.getBody().get("removedByCategory");
        assertEquals(1, categories.get("session_terminal").asInt(), "the logged-out family is reclaimed");
        assertTrue(report.getBody().get("totalRemoved").asInt() >= 3,
                "session + its token records are all removed");
        System.out.printf("[http-reclamation] totalRemoved=%d categories=%s%n",
                report.getBody().get("totalRemoved").asInt(), categories);
    }

    private JsonNode login(String caller, String subject) {
        ResponseEntity<String> response = restTemplate.postForEntity(url("/api/auth/login"),
                jsonEntity(caller, "{\"subject\":\"" + subject + "\"}"), String.class);
        try {
            return JSON.readTree(response.getBody());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private org.springframework.http.HttpEntity<String> jsonEntity(String caller, String body) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        headers.set("X-Caller-Id", caller);
        return new org.springframework.http.HttpEntity<>(body, headers);
    }
}
