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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * HTTP-level rate-limit boundary tests using the default configuration
 * (5 requests / 1000ms sliding window per caller) and a controlled clock.
 * Runs in a dedicated context so the counters are never shared with the
 * high-limit auth-flow integration tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = {com.github.h3yow.authtokenrotationjava.Application.class, TestClockConfig.class})
class RateLimitHttpIntegrationTest {

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
    @DisplayName("HTTP boundary: 5 requests pass, the 6th is 429 with a distinct code; sliding past the window resets")
    void boundaryBlockingAndWindowReset() {
        String caller = "rl-http-dave";
        for (int i = 1; i <= 5; i++) {
            ResponseEntity<JsonNode> response = login(caller, "dave-" + i);
            assertEquals(HttpStatus.OK, response.getStatusCode(), "request " + i + " must pass");
        }

        ResponseEntity<JsonNode> blocked = login(caller, "dave-6");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, blocked.getStatusCode());
        assertEquals("rate_limit_exceeded", blocked.getBody().get("error").asText());
        assertEquals(caller, blocked.getBody().get("callerId").asText());

        // Exactly at the window edge the same-instant batch ages out together.
        clock.advanceMillis(1_000);
        ResponseEntity<JsonNode> atBoundary = login(caller, "dave-at-boundary");
        assertEquals(HttpStatus.OK, atBoundary.getStatusCode(), "a boundary request belongs to the new window");

        System.out.println("[http-rate-limit-boundary] callerId=rl-http-dave allowed=5 blocked=429x1 "
                + "boundary=allowed reason=rate_limit_exceeded_then_sliding_window_reset");
    }

    @Test
    @DisplayName("HTTP isolation: a saturated caller never throttles a different caller")
    void callersAreIsolatedOverHttp() {
        String noisy = "rl-http-noisy";
        for (int i = 0; i < 5; i++) {
            assertEquals(HttpStatus.OK, login(noisy, "noisy-" + i).getStatusCode());
        }
        for (int extra = 0; extra < 3; extra++) {
            assertEquals(HttpStatus.TOO_MANY_REQUESTS, login(noisy, "noisy-extra-" + extra).getStatusCode());
        }

        String quiet = "rl-http-quiet";
        for (int i = 0; i < 5; i++) {
            assertEquals(HttpStatus.OK, login(quiet, "quiet-" + i).getStatusCode(),
                    "an isolated caller is never affected by a noisy neighbour");
        }
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, login(quiet, "quiet-extra").getStatusCode());
        System.out.println("[http-rate-limit-isolation] noisy=rl-http-noisy(saturated) "
                + "quiet=rl-http-quiet(independent)");
    }

    private ResponseEntity<JsonNode> login(String callerId, String subject) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Caller-Id", callerId);
        try {
            HttpEntity<String> entity = new HttpEntity<>(JSON.writeValueAsString(Map.of("subject", subject)),
                    headers);
            ResponseEntity<String> response = restTemplate.postForEntity(url("/api/auth/login"), entity,
                    String.class);
            JsonNode body = response.getBody() == null ? null : JSON.readTree(response.getBody());
            return new ResponseEntity<>(body, response.getStatusCode());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
