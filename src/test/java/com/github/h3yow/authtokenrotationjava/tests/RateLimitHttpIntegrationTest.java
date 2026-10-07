package com.github.h3yow.authtokenrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
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

/**
 * HTTP-level rate-limit tests for the <b>server-attested trust boundary</b>,
 * using the default configuration (5 requests / 1000ms window) and a controlled
 * clock. Quota is charged to the credential owner, never to the declared
 * header; login/ops use an isolated unauthenticated bucket and invalid
 * credentials an isolated untrusted bucket.
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

    @BeforeEach
    void resetWindows() {
        // Every test starts past one full window, so trusted/untrusted/
        // unauthenticated buckets are all empty regardless of execution order.
        clock.advanceMillis(1_001);
    }

    @Test
    @DisplayName("trusted boundary: a caller is charged by its attested token owner; 5 pass then 429, window reset at boundary")
    void trustedBoundaryAndWindowReset() {
        String caller = "rl-http-dave";
        JsonNode login = login(caller, "dave").getBody();
        String access = login.get("accessToken").asText();

        // The login itself was charged to the unauthenticated bucket, so caller
        // "rl-http-dave" starts with an empty trusted window: exactly 5 passes.
        for (int i = 1; i <= 5; i++) {
            ResponseEntity<JsonNode> response = resource(caller, access);
            assertEquals(HttpStatus.OK, response.getStatusCode(), "trusted request " + i + " must pass");
        }
        ResponseEntity<JsonNode> blocked = resource(caller, access);
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, blocked.getStatusCode());
        assertEquals("rate_limit_exceeded", blocked.getBody().get("error").asText());

        // At the window edge the same-instant batch ages out together.
        clock.advanceMillis(1_000);
        assertEquals(HttpStatus.OK, resource(caller, access).getStatusCode(),
                "a boundary request belongs to the new window");

        System.out.println("[http-rate-limit-boundary] tier=TRUSTED callerId=rl-http-dave "
                + "allowed=5 blocked=429x1 boundary=allowed");
    }

    @Test
    @DisplayName("spoofing the header cannot spend another caller's quota; the attacker is charged to the token owner or the untrusted bucket")
    void spoofedIdentityCannotConsumeRealQuota() {
        String victim = "rl-victim";
        String attacker = "rl-attacker";
        JsonNode victimLogin = login(victim, "vic").getBody();
        JsonNode attackerLogin = login(attacker, "att").getBody();

        // The attacker presents its OWN valid token but declares the victim's
        // identity. The charge goes to the attested OWNER (attacker), so the
        // victim's quota is untouched. (4 < limit, so all execute.)
        for (int i = 0; i < 4; i++) {
            ResponseEntity<JsonNode> spoof = resource(victim, attackerLogin.get("accessToken").asText());
            assertEquals(HttpStatus.UNAUTHORIZED, spoof.getStatusCode(),
                    "header spoof is rejected as caller mismatch");
            assertEquals("access_token_caller_mismatch", spoof.getBody().get("error").asText());
        }
        // Garbage/forged credentials get their own distinct security code and
        // are charged only to the untrusted bucket (4 total < limit): never the
        // victim's quota.
        ResponseEntity<JsonNode> forgedAccess = resource(victim, "atk_not-a-real-token");
        assertEquals(HttpStatus.UNAUTHORIZED, forgedAccess.getStatusCode());
        assertEquals("access_token_unknown", forgedAccess.getBody().get("error").asText());
        ResponseEntity<JsonNode> forgedRefresh = refresh(victim, "rtk_not-a-real-token");
        assertEquals(HttpStatus.UNAUTHORIZED, forgedRefresh.getStatusCode());
        assertEquals("refresh_token_unknown", forgedRefresh.getBody().get("error").asText());

        // The victim's own first 5 requests must still be admitted: its window
        // was never charged by the spoofed/forged traffic above.
        for (int i = 1; i <= 5; i++) {
            ResponseEntity<JsonNode> ok = resource(victim, victimLogin.get("accessToken").asText());
            assertEquals(HttpStatus.OK, ok.getStatusCode(),
                    "victim request " + i + " must pass: forged traffic never charged the victim");
        }
        ResponseEntity<JsonNode> sixth = resource(victim, victimLogin.get("accessToken").asText());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, sixth.getStatusCode(),
                "the victim's 6th own request is limited only by its own usage");

        System.out.println("[http-rate-limit-trust] spoofedHeader=rl-victim(attackerToken)x4->caller_mismatch "
                + "forgedCredentials=2->unknown victimOwnAllowed=5 victimOwn6th=429 "
                + "real_caller_spoofed_quota_charged=false");
    }

    @Test
    @DisplayName("two real callers remain isolated from each other at the trusted tier")
    void realCallersStayIsolated() {
        String noisy = "rl-http-noisy";
        String quiet = "rl-http-quiet";
        JsonNode noisyLogin = login(noisy, "noisy").getBody();
        JsonNode quietLogin = login(quiet, "quiet").getBody();

        for (int i = 0; i < 5; i++) {
            assertEquals(HttpStatus.OK, resource(noisy, noisyLogin.get("accessToken").asText()).getStatusCode());
        }
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,
                resource(noisy, noisyLogin.get("accessToken").asText()).getStatusCode());

        for (int i = 0; i < 5; i++) {
            assertEquals(HttpStatus.OK, resource(quiet, quietLogin.get("accessToken").asText()).getStatusCode(),
                    "a real isolated caller is never affected by a noisy neighbour");
        }
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,
                resource(quiet, quietLogin.get("accessToken").asText()).getStatusCode());
        System.out.println("[http-rate-limit-isolation] noisy=rl-http-noisy(saturated) "
                + "quiet=rl-http-quiet(independent)");
    }

    @Test
    @DisplayName("the unauthenticated login bucket is isolated from real callers")
    void unauthenticatedBucketIsIsolated() {
        // Saturate the shared unauthenticated bucket with login attempts.
        for (int i = 0; i < 5; i++) {
            assertEquals(HttpStatus.OK, login("rl-login-flood-" + i, "s" + i).getStatusCode());
        }
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, login("rl-login-flood-extra", "sx").getStatusCode(),
                "the 6th unauthenticated login in the window is limited");

        // A real caller presenting a valid credential is unaffected by that.
        String victim = "rl-login-victim";
        // Need a token first; wait for the unauthenticated window to reset to mint it.
        clock.advanceMillis(1_000);
        JsonNode victimLogin = login(victim, "vic").getBody();
        assertEquals(HttpStatus.OK, resource(victim, victimLogin.get("accessToken").asText()).getStatusCode(),
                "unauthenticated flood never touched the real caller's trusted bucket");
        System.out.println("[http-rate-limit-unauth] loginFlood=5x200+1x429 realCallerUnaffected=true");
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

    private ResponseEntity<JsonNode> resource(String declaredCallerId, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Caller-Id", declaredCallerId);
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }
        try {
            ResponseEntity<String> response = restTemplate.exchange(url("/api/auth/resource"),
                    org.springframework.http.HttpMethod.POST, new HttpEntity<>("", headers), String.class);
            JsonNode body = response.getBody() == null ? null : JSON.readTree(response.getBody());
            return new ResponseEntity<>(body, response.getStatusCode());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseEntity<JsonNode> refresh(String declaredCallerId, String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Caller-Id", declaredCallerId);
        try {
            HttpEntity<String> entity = new HttpEntity<>(
                    JSON.writeValueAsString(Map.of("refreshToken", refreshToken)), headers);
            ResponseEntity<String> response = restTemplate.postForEntity(url("/api/auth/refresh"), entity,
                    String.class);
            JsonNode body = response.getBody() == null ? null : JSON.readTree(response.getBody());
            return new ResponseEntity<>(body, response.getStatusCode());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
