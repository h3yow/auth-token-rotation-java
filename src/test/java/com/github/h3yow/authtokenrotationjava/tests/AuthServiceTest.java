package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.service.TokenFactory;
import com.github.h3yow.authtokenrotationjava.store.InMemoryTokenStore;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the rotation, replay and revocation core. Every scenario
 * prints caller identity, token state and the decision basis via the service's
 * own SLF4J logs.
 */
class AuthServiceTest {

    private MutableClock clock;
    private AuthService authService;
    private TokenStore store;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setAccessTokenTtlMillis(300_000);
        properties.setRefreshTokenTtlMillis(3_600_000);
        store = new InMemoryTokenStore();
        authService = new AuthService(store, new TokenFactory(), properties, clock);
    }

    @Test
    @DisplayName("login issues a usable pair")
    void loginIssuesUsablePair() {
        TokenPair pair = authService.login("alice", "caller-A");
        AccessVerification verification = authService.verifyAccessToken(pair.accessToken(), "caller-A");
        assertTrue(verification.accepted(), "freshly issued access token must verify");
        assertEquals("access_token_valid", verification.reason());
    }

    @Test
    @DisplayName("sequential replay of a rotated refresh token revokes the whole chain")
    void sequentialReplayRevokesChain() {
        TokenPair first = authService.login("bob", "caller-B");

        // Legitimate rotation: old refresh token dies atomically.
        TokenPair second = authService.rotate(first.refreshToken(), "caller-B");
        assertNotEquals(first.refreshToken(), second.refreshToken());

        // Replay of the old (already rotated) token.
        AuthException replay = assertThrowsAuth(() -> authService.rotate(first.refreshToken(), "caller-B"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, replay.getErrorCode());

        // Chain-wide consequence: the new (previously valid) refresh token is
        // now dead as well, with a distinct chain-level conclusion.
        AuthException afterReplay = assertThrowsAuth(() -> authService.rotate(second.refreshToken(), "caller-B"));
        assertEquals(AuthErrorCode.CHAIN_REVOKED_REPLAY, afterReplay.getErrorCode());

        // Still-unexpired access tokens fail immediately, distinguishable as replay.
        AccessVerification access = authService.verifyAccessToken(second.accessToken(), "caller-B");
        assertFalse(access.accepted());
        assertEquals(AuthErrorCode.ACCESS_TOKEN_REVOKED_REPLAY.code(), access.reason());
    }

    @Test
    @DisplayName("concurrent use of one refresh token allows exactly one success")
    void concurrentRefreshExactlyOneSuccess() throws Exception {
        TokenPair pair = authService.login("carol", "caller-C");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger sequentialReplay = new AtomicInteger();
        AtomicInteger concurrentReplay = new AtomicInteger();
        AtomicInteger chainRevoked = new AtomicInteger();
        AtomicInteger otherErrors = new AtomicInteger();
        java.util.List<String> otherReasons = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    try {
                        TokenPair rotated = authService.rotate(pair.refreshToken(), "caller-C");
                        if (!rotated.accessToken().isBlank()) {
                            success.incrementAndGet();
                        }
                    } catch (AuthException ex) {
                        // A batch-released thread may be scheduled into rotate()
                        // after the winner's gate has already closed; it then
                        // genuinely arrives later and is classified SEQUENTIAL.
                        // Threads that overlap the winner are CONCURRENT, and
                        // threads arriving after the first loser are CHAIN_*.
                        // All three are distinguishable replay-family verdicts;
                        // the deterministic guarantees are "exactly one success",
                        // "no other reason" and "the whole chain is compromised".
                        switch (ex.getErrorCode()) {
                            case REFRESH_TOKEN_REPLAY_CONCURRENT -> concurrentReplay.incrementAndGet();
                            case REFRESH_TOKEN_REPLAY_SEQUENTIAL -> sequentialReplay.incrementAndGet();
                            case CHAIN_REVOKED_REPLAY -> chainRevoked.incrementAndGet();
                            default -> {
                                otherErrors.incrementAndGet();
                                otherReasons.add(ex.getErrorCode().name());
                            }
                        }
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(ie);
                }
            });
        }
        ready.await();
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "all refresh attempts must finish");

        int replayFailures = sequentialReplay.get() + concurrentReplay.get() + chainRevoked.get();
        System.out.printf("[concurrent-refresh] callerId=caller-C threads=%d success=%d sequentialReplay=%d "
                        + "concurrentReplay=%d chainRevoked=%d other=%d otherReasons=%s%n",
                threads, success.get(), sequentialReplay.get(), concurrentReplay.get(),
                chainRevoked.get(), otherErrors.get(), otherReasons);

        assertEquals(1, success.get(), "exactly one concurrent refresh may succeed");
        assertEquals(0, otherErrors.get(),
                "no unexplained failures allowed, got: " + otherReasons);
        assertEquals(threads - 1, replayFailures,
                "every losing attempt must be a distinguishable replay/chain conclusion");

        // The winning pair must also be unusable afterwards: the chain was
        // compromised by the concurrent duplicate presentation.
        for (Session session : allSessions()) {
            assertEquals(Session.Status.COMPROMISED, session.getStatus());
        }
    }

    @Test
    @DisplayName("concurrent replay classification is deterministic when the gate is open")
    void heldGateProducesConcurrentVerdict() {
        TokenPair pair = authService.login("dave", "caller-D");
        String familyId = pair.familyId();

        // Reproduce the exact state a losing thread sees: the winner has
        // consumed the token and the gate has not closed yet. We obtain that
        // state from inside the family lock while holding the gate on a
        // different attempt id, which is the definition of overlap.
        String loserAttempt = UUID.randomUUID().toString();
        assertTrue(store.tryAcquireFamilyGate(familyId, loserAttempt));
        try {
            RefreshTokenRecord record = store.findRefreshToken(pair.refreshToken());
            assertTrue(record.markRotated(clock.nowMillis()), "winner consumes the token once");
            // The loser arrives now: gate open (it lost acquisition), token ROTATED.
            AuthException ex = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-D"));
            assertEquals(AuthErrorCode.REFRESH_TOKEN_REPLAY_CONCURRENT, ex.getErrorCode());
        } finally {
            store.releaseFamilyGate(familyId, loserAttempt);
        }

        // Once the overlap is detected, the whole chain is compromised.
        Session session = store.findSession(familyId);
        assertEquals(Session.Status.COMPROMISED, session.getStatus());
    }

    @Test
    @DisplayName("logout instantly invalidates unexpired access tokens and refresh tokens")
    void logoutPropagatesImmediately() {
        TokenPair pair = authService.login("erin", "caller-E");
        authService.logout(pair.refreshToken(), "caller-E");

        AccessVerification access = authService.verifyAccessToken(pair.accessToken(), "caller-E");
        assertFalse(access.accepted());
        assertEquals(AuthErrorCode.ACCESS_TOKEN_REVOKED_LOGOUT.code(), access.reason());

        AuthException refresh = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-E"));
        assertEquals(AuthErrorCode.CHAIN_REVOKED_LOGOUT, refresh.getErrorCode());
    }

    @Test
    @DisplayName("revoked access token stays rejected across the whole chain but not other sessions")
    void revocationIsScopedToFamily() {
        TokenPair victim = authService.login("frank", "caller-F");
        TokenPair other = authService.login("grace", "caller-G");
        authService.logout(victim.refreshToken(), "caller-F");

        assertFalse(authService.verifyAccessToken(victim.accessToken(), "caller-F").accepted());
        AccessVerification untouched = authService.verifyAccessToken(other.accessToken(), "caller-G");
        assertTrue(untouched.accepted(), "an unrelated session must never be affected");
    }

    @Test
    @DisplayName("expired tokens are rejected with their own reason")
    void expiredTokensHaveDistinctReason() {
        TokenPair pair = authService.login("heidi", "caller-H");
        clock.advanceMillis(300_001);
        AccessVerification access = authService.verifyAccessToken(pair.accessToken(), "caller-H");
        assertFalse(access.accepted());
        assertEquals(AuthErrorCode.ACCESS_TOKEN_EXPIRED.code(), access.reason());

        clock.advanceMillis(3_600_000);
        AuthException refresh = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-H"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_EXPIRED, refresh.getErrorCode());
    }

    @Test
    @DisplayName("a caller may not use another caller's token")
    void callerIsolationOnTokens() {
        TokenPair pair = authService.login("ivan", "caller-I");
        AccessVerification access = authService.verifyAccessToken(pair.accessToken(), "caller-J");
        assertFalse(access.accepted());
        assertEquals(AuthErrorCode.ACCESS_TOKEN_CALLER_MISMATCH.code(), access.reason());

        AuthException refresh = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-J"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, refresh.getErrorCode());
    }

    private AuthException assertThrowsAuth(Runnable runnable) {
        try {
            runnable.run();
        } catch (AuthException ex) {
            return ex;
        }
        throw new AssertionError("expected AuthException");
    }

    private java.util.List<Session> allSessions() {
        java.util.List<Session> sessions = new java.util.ArrayList<>();
        store.forEachSession(sessions::add);
        return sessions;
    }
}
