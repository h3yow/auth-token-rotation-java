package com.github.h3yow.authtokenrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import com.github.h3yow.authtokenrotationjava.support.TestClockConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests over real HTTP. Rate-limit windows are driven by the
 * {@link MutableClock}, so boundary results are fully deterministic.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = {com.github.h3yow.authtokenrotationjava.Application.class, TestClockConfig.class})
@TestPropertySource(properties = {
        // High enough that auth-flow tests are never throttled; the boundary
        // behaviour is covered separately in RateLimitHttpIntegrationTest.
        "auth.security.rate-limit-max-requests=10000"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthHttpIntegrationTest {

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

    private HttpHeaders headers(String callerId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Caller-Id", callerId);
        return headers;
    }

    @Test
    @Order(1)
    @DisplayName("happy path over HTTP: login, access, rotate, old access token remains usable until expiry")
    void happyPath() {
        String caller = "http-alice";
        JsonNode login = post("/api/auth/login", caller, Map.of("subject", "alice")).getBody();
        String accessToken = login.get("accessToken").asText();
        String refreshToken = login.get("refreshToken").asText();

        JsonNode resource = resource(caller, accessToken).getBody();
        assertEquals("ok", resource.get("status").asText());
        assertEquals("alice", resource.get("subject").asText());

        JsonNode rotated = post("/api/auth/refresh", caller, Map.of("refreshToken", refreshToken)).getBody();
        assertNotEquals(refreshToken, rotated.get("refreshToken").asText());

        // New access token works.
        assertEquals("ok", resource(caller, rotated.get("accessToken").asText()).getBody().get("status").asText());

        // A true post-hoc replay happens only after the benign overlap window.
        clock.advanceMillis(2_001);

        // Old refresh token replayed after the window elapsed: sequential replay, chain killed.
        ResponseEntity<JsonNode> replay = post("/api/auth/refresh", caller, Map.of("refreshToken", refreshToken));
        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        assertEquals("refresh_token_replay_sequential", replay.getBody().get("error").asText());

        // Previously good new access token is now immediately dead, replay reason distinguishable.
        ResponseEntity<JsonNode> deadAccess = resource(caller, rotated.get("accessToken").asText());
        assertEquals(HttpStatus.UNAUTHORIZED, deadAccess.getStatusCode());
        assertEquals("access_token_revoked_replay", deadAccess.getBody().get("error").asText());
    }

    @Test
    @Order(2)
    @DisplayName("concurrent refresh of the same token over HTTP: exactly one 200, rest identical 409 conflicts, chain stays alive")
    void concurrentRefreshOverHttp() throws Exception {
        String caller = "http-bob";
        JsonNode login = post("/api/auth/login", caller, Map.of("subject", "bob")).getBody();
        String refreshToken = login.get("refreshToken").asText();

        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger conflict = new AtomicInteger();
        AtomicInteger unexpected = new AtomicInteger();
        java.util.List<JsonNode> winningBodies = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        java.util.List<String> unexpectedCodes = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    ResponseEntity<JsonNode> response = post("/api/auth/refresh", caller,
                            Map.of("refreshToken", refreshToken));
                    if (response.getStatusCode() == HttpStatus.OK) {
                        ok.incrementAndGet();
                        winningBodies.add(response.getBody());
                    } else {
                        String error = response.getBody().get("error").asText();
                        // Scheduling-independent benign verdict: every losing
                        // attempt of the same batch is the same 409 conflict.
                        if ("refresh_concurrent_conflict".equals(error)
                                && response.getStatusCode() == HttpStatus.CONFLICT) {
                            conflict.incrementAndGet();
                        } else {
                            unexpected.incrementAndGet();
                            unexpectedCodes.add(response.getStatusCode() + ":" + error);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await();
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        System.out.printf("[http-concurrent-refresh] callerId=%s total=%d ok=%d conflict=%d unexpected=%d codes=%s%n",
                caller, threads, ok.get(), conflict.get(), unexpected.get(), unexpectedCodes);
        assertEquals(1, ok.get(), "exactly one concurrent refresh succeeds");
        assertEquals(threads - 1, conflict.get(), "every loser gets the same benign 409 conflict");
        assertEquals(0, unexpected.get(), "no other verdict allowed: " + unexpectedCodes);

        // Benign concurrency leaves the chain healthy: the winner's new access
        // token verifies and its new refresh token rotates again.
        assertEquals(1, winningBodies.size());
        JsonNode winner = winningBodies.get(0);
        assertEquals(HttpStatus.OK,
                resource(caller, winner.get("accessToken").asText()).getStatusCode());
        ResponseEntity<JsonNode> next = post("/api/auth/refresh", caller,
                Map.of("refreshToken", winner.get("refreshToken").asText()));
        assertEquals(HttpStatus.OK, next.getStatusCode(), "the chain keeps rotating after a benign conflict");
        assertEquals(HttpStatus.OK,
                resource(caller, next.getBody().get("accessToken").asText()).getStatusCode());

        // The truly later replay (after the overlap window) still kills the chain.
        clock.advanceMillis(2_001);
        ResponseEntity<JsonNode> lateReplay = post("/api/auth/refresh", caller,
                Map.of("refreshToken", winner.get("refreshToken").asText()));
        assertEquals(HttpStatus.UNAUTHORIZED, lateReplay.getStatusCode());
        assertEquals("refresh_token_replay_sequential", lateReplay.getBody().get("error").asText());
    }

    @Test
    @Order(3)
    @DisplayName("logout propagates immediately to a still-valid access token")
    void logoutPropagatesImmediately() {
        String caller = "http-carol";
        JsonNode login = post("/api/auth/login", caller, Map.of("subject", "carol")).getBody();
        String accessToken = login.get("accessToken").asText();
        String refreshToken = login.get("refreshToken").asText();

        assertEquals(HttpStatus.OK, resource(caller, accessToken).getStatusCode());
        assertEquals(HttpStatus.OK, post("/api/auth/logout", caller, Map.of("refreshToken", refreshToken))
                .getStatusCode());

        ResponseEntity<JsonNode> after = resource(caller, accessToken);
        assertEquals(HttpStatus.UNAUTHORIZED, after.getStatusCode());
        assertEquals("access_token_revoked_logout", after.getBody().get("error").asText());

        ResponseEntity<JsonNode> refreshAfter = post("/api/auth/refresh", caller,
                Map.of("refreshToken", refreshToken));
        assertEquals("chain_revoked_logout", refreshAfter.getBody().get("error").asText());
    }

    @Test
    @Order(5)
    @DisplayName("missing or foreign caller identity is rejected with distinct reasons")
    void missingCallerAndTokenCallerIsolation() {
        // No caller header at all -> 400 distinct code.
        HttpHeaders noCaller = new HttpHeaders();
        noCaller.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<JsonNode> missing = restTemplate.exchange(url("/api/auth/login"), HttpMethod.POST,
                new HttpEntity<>("{\"subject\":\"x\"}", noCaller), JsonNode.class);
        assertEquals(HttpStatus.BAD_REQUEST, missing.getStatusCode());
        assertEquals("caller_identity_missing", missing.getBody().get("error").asText());

        // Token minted for one caller, presented by another -> distinct 401.
        JsonNode login = post("/api/auth/login", "http-frank", Map.of("subject", "frank")).getBody();
        ResponseEntity<JsonNode> foreign = resource("http-grace", login.get("accessToken").asText());
        assertEquals(HttpStatus.UNAUTHORIZED, foreign.getStatusCode());
        assertEquals("access_token_caller_mismatch", foreign.getBody().get("error").asText());
    }

    private ResponseEntity<JsonNode> post(String path, String callerId, Map<String, String> body) {
        HttpEntity<String> entity = new HttpEntity<>(writeJson(body), headers(callerId));
        ResponseEntity<String> response = restTemplate.postForEntity(url(path), entity, String.class);
        return toJsonResponse(response);
    }

    private ResponseEntity<JsonNode> resource(String callerId, String accessToken) {
        HttpHeaders h = headers(callerId);
        h.setBearerAuth(accessToken);
        ResponseEntity<String> response = restTemplate.exchange(url("/api/auth/resource"), HttpMethod.POST,
                new HttpEntity<>("", h), String.class);
        return toJsonResponse(response);
    }

    private ResponseEntity<JsonNode> toJsonResponse(ResponseEntity<String> response) {
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

    private String writeJson(Map<String, String> body) {
        try {
            return JSON.writeValueAsString(body);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
