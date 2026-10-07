package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
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

    private static final long GRACE_MILLIS = 30_000L;

    private MutableClock clock;
    private AuthService authService;
    private TokenStore store;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setAccessTokenTtlMillis(300_000);
        properties.setRefreshTokenTtlMillis(3_600_000);
        properties.setRefreshConcurrentGraceMillis(GRACE_MILLIS);
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
    @DisplayName("sequential replay AFTER the rotation round ended revokes the whole chain")
    void sequentialReplayRevokesChain() {
        TokenPair first = authService.login("bob", "caller-B");

        // Legitimate rotation: old refresh token dies atomically.
        TokenPair second = authService.rotate(first.refreshToken(), "caller-B");
        assertNotEquals(first.refreshToken(), second.refreshToken());

        // The rotation round has fully ended AND the benign-concurrency grace
        // has elapsed before the old credential is presented again.
        clock.advanceMillis(GRACE_MILLIS + 1);
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

        assertEquals(Session.Status.COMPROMISED, store.findSession(first.familyId()).getStatus());
    }

    @Test
    @DisplayName("benign concurrent batch: exactly one success, every loser gets the same conflict, chain survives")
    void concurrentRefreshExactlyOneSuccess() throws Exception {
        TokenPair pair = authService.login("carol", "caller-C");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger conflicts = new AtomicInteger();
        AtomicInteger otherErrors = new AtomicInteger();
        java.util.List<String> otherReasons = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        java.util.List<TokenPair> winningPairs = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    try {
                        TokenPair rotated = authService.rotate(pair.refreshToken(), "caller-C");
                        winningPairs.add(rotated);
                        success.incrementAndGet();
                    } catch (AuthException ex) {
                        if (ex.getErrorCode() == AuthErrorCode.REFRESH_CONFLICT_CONCURRENT) {
                            conflicts.incrementAndGet();
                        } else {
                            otherErrors.incrementAndGet();
                            otherReasons.add(ex.getErrorCode().name());
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

        System.out.printf("[concurrent-refresh] callerId=caller-C threads=%d success=%d conflict=%d "
                        + "other=%d otherReasons=%s%n",
                threads, success.get(), conflicts.get(), otherErrors.get(), otherReasons);

        assertEquals(1, success.get(), "exactly one concurrent refresh may succeed");
        assertEquals(threads - 1, conflicts.get(), "every loser must land on the single conflict verdict");
        assertEquals(0, otherErrors.get(), "no unexplained failures allowed, got: " + otherReasons);

        // Benign concurrency must NOT kill the chain.
        Session session = store.findSession(pair.familyId());
        assertEquals(Session.Status.ACTIVE, session.getStatus(), "benign concurrency must not revoke the chain");

        // The winner's new credentials still work: access granted, and the new
        // refresh token can itself be rotated again.
        TokenPair winner = winningPairs.get(0);
        AccessVerification access = authService.verifyAccessToken(winner.accessToken(), "caller-C");
        assertTrue(access.accepted(), "winner access token must still verify after benign concurrency");
        TokenPair next = authService.rotate(winner.refreshToken(), "caller-C");
        assertNotEquals(winner.refreshToken(), next.refreshToken());
        assertTrue(authService.verifyAccessToken(next.accessToken(), "caller-C").accepted());
    }

    @Test
    @DisplayName("concurrent verdict is stable across repeated runs of the same batch")
    void concurrentVerdictIsStableAcrossRepeatedRuns() throws Exception {
        TokenPair pair = authService.login("carol2", "caller-R");
        int threads = 12;
        TokenPair winner = null;

        for (int run = 1; run <= 3; run++) {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger success = new AtomicInteger();
            AtomicInteger conflicts = new AtomicInteger();
            AtomicInteger other = new AtomicInteger();
            java.util.List<TokenPair> wins = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        ready.countDown();
                        start.await();
                        try {
                            wins.add(authService.rotate(pair.refreshToken(), "caller-R"));
                            success.incrementAndGet();
                        } catch (AuthException ex) {
                            if (ex.getErrorCode() == AuthErrorCode.REFRESH_CONFLICT_CONCURRENT) {
                                conflicts.incrementAndGet();
                            } else {
                                other.incrementAndGet();
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
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

            if (run == 1) {
                assertEquals(1, success.get(), "first run has exactly one winner");
                winner = wins.get(0);
            } else {
                assertEquals(0, success.get(), "a re-run of the consumed token never succeeds again");
            }
            assertEquals(run == 1 ? threads - 1 : threads, conflicts.get(),
                    "run " + run + ": every non-winning request is the same conflict");
            assertEquals(0, other.get(), "run " + run + ": no other verdict is possible");

            System.out.printf("[concurrent-refresh-rerun] callerId=caller-R run=%d threads=%d success=%d "
                            + "conflict=%d other=%d sessionStatus=%s%n", run, threads, success.get(),
                    conflicts.get(), other.get(), store.findSession(pair.familyId()).getStatus());
        }

        // The session never got compromised by the retries, and the winner's
        // credentials from run 1 remain fully usable.
        assertEquals(Session.Status.ACTIVE, store.findSession(pair.familyId()).getStatus());
        assertTrue(authService.verifyAccessToken(winner.accessToken(), "caller-R").accepted());
        TokenPair continued = authService.rotate(winner.refreshToken(), "caller-R");
        assertTrue(authService.verifyAccessToken(continued.accessToken(), "caller-R").accepted());
    }

    @Test
    @DisplayName("immediate reuse of the consumed token is the benign conflict, not a replay")
    void immediateReuseIsBenignConflict() {
        TokenPair pair = authService.login("dave", "caller-D");
        TokenPair winner = authService.rotate(pair.refreshToken(), "caller-D");

        // No time passes at all: a slow-but-same-batch retry.
        AuthException ex = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-D"));
        assertEquals(AuthErrorCode.REFRESH_CONFLICT_CONCURRENT, ex.getErrorCode());
        assertEquals(Session.Status.ACTIVE, store.findSession(pair.familyId()).getStatus());
        assertTrue(authService.verifyAccessToken(winner.accessToken(), "caller-D").accepted());
    }

    @Test
    @DisplayName("grace boundary: reuse exactly at grace end is benign; one millisecond later is replay")
    void graceBoundaryIsDeterministic() {
        TokenPair pair = authService.login("judy", "caller-K");
        TokenPair winner = authService.rotate(pair.refreshToken(), "caller-K");

        clock.advanceMillis(GRACE_MILLIS);
        AuthException atBoundary = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-K"));
        assertEquals(AuthErrorCode.REFRESH_CONFLICT_CONCURRENT, atBoundary.getErrorCode(),
                "age == grace is still inside the inclusive benign window");
        assertEquals(Session.Status.ACTIVE, store.findSession(pair.familyId()).getStatus());

        clock.advanceMillis(1);
        AuthException after = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-K"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, after.getErrorCode());
        assertEquals(Session.Status.COMPROMISED, store.findSession(pair.familyId()).getStatus());
        assertFalse(authService.verifyAccessToken(winner.accessToken(), "caller-K").accepted());
    }

    @Test
    @DisplayName("reuse after the successor itself was consumed is a replay even inside the grace window")
    void successorConsumedMeansReplayRegardlessOfTiming() {
        TokenPair first = authService.login("kate", "caller-L");
        TokenPair second = authService.rotate(first.refreshToken(), "caller-L");
        // Legit client keeps rotating: second -> third. The round for the first
        // token has demonstrably ended even though zero wall time advanced.
        TokenPair third = authService.rotate(second.refreshToken(), "caller-L");

        AuthException replay = assertThrowsAuth(() -> authService.rotate(first.refreshToken(), "caller-L"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, replay.getErrorCode());
        assertEquals(Session.Status.COMPROMISED, store.findSession(first.familyId()).getStatus());
        assertFalse(authService.verifyAccessToken(third.accessToken(), "caller-L").accepted());
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
}
