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

        // A reuse only after the benign overlap window has elapsed is the real
        // post-hoc replay that must kill the chain.
        clock.advanceMillis(2_001);

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
    @DisplayName("concurrent use of one refresh token: exactly one success, all losers get the same 409 conflict and the chain stays healthy")
    void concurrentRefreshExactlyOneSuccess() throws Exception {
        TokenPair pair = authService.login("carol", "caller-C");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger conflict = new AtomicInteger();
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
                        // Under the scheduling-independent first-touch protocol
                        // every losing attempt of the same concurrent batch must
                        // land on exactly one benign verdict, regardless of how
                        // late the OS schedules the thread.
                        if (ex.getErrorCode() == AuthErrorCode.REFRESH_CONCURRENT_CONFLICT) {
                            conflict.incrementAndGet();
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
                threads, success.get(), conflict.get(), otherErrors.get(), otherReasons);

        assertEquals(1, success.get(), "exactly one concurrent refresh may succeed");
        assertEquals(threads - 1, conflict.get(),
                "every losing attempt must get the same benign concurrent-conflict verdict");
        assertEquals(0, otherErrors.get(),
                "no unexplained failures allowed, got: " + otherReasons);

        // Benign concurrency must not harm the chain: the session stays ACTIVE.
        Session session = store.findSession(pair.familyId());
        assertEquals(Session.Status.ACTIVE, session.getStatus(),
                "a benign concurrent batch must never invalidate the chain");

        // The winner's freshly issued pair must still work: new access token
        // verifies, and the new refresh token rotates again.
        assertEquals(1, winningPairs.size());
        TokenPair winnerPair = winningPairs.get(0);
        AccessVerification winnerAccess =
                authService.verifyAccessToken(winnerPair.accessToken(), "caller-C");
        assertTrue(winnerAccess.accepted(), "winner's new access token must remain usable");
        TokenPair next = authService.rotate(winnerPair.refreshToken(), "caller-C");
        AccessVerification nextAccess = authService.verifyAccessToken(next.accessToken(), "caller-C");
        assertTrue(nextAccess.accepted(), "the chain must continue rotating after a benign conflict");
    }

    @Test
    @DisplayName("re-running a concurrent batch always yields the same verdict multiset: 1 success + N conflicts")
    void concurrentBatchVerdictIsStableAcrossRuns() throws Exception {
        for (int run = 0; run < 5; run++) {
            TokenPair pair = authService.login("carol-run-" + run, "caller-C");
            int threads = 12;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger success = new AtomicInteger();
            AtomicInteger conflict = new AtomicInteger();
            AtomicInteger other = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        ready.countDown();
                        start.await();
                        try {
                            authService.rotate(pair.refreshToken(), "caller-C");
                            success.incrementAndGet();
                        } catch (AuthException ex) {
                            if (ex.getErrorCode() == AuthErrorCode.REFRESH_CONCURRENT_CONFLICT) {
                                conflict.incrementAndGet();
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
            System.out.printf("[concurrent-refresh-rerun] run=%d callerId=caller-C success=%d conflict=%d other=%d%n",
                    run, success.get(), conflict.get(), other.get());
            assertEquals(1, success.get(), "run " + run + ": exactly one success");
            assertEquals(threads - 1, conflict.get(), "run " + run + ": every loser is the same conflict");
            assertEquals(0, other.get(), "run " + run + ": no other verdict may appear");
            assertEquals(Session.Status.ACTIVE, store.findSession(pair.familyId()).getStatus(),
                    "run " + run + ": chain must survive");
        }
    }

    @Test
    @DisplayName("a duplicate presentation inside the overlap window is a benign conflict, not a replay")
    void withinOverlapWindowIsConcurrentConflict() {
        TokenPair pair = authService.login("dave", "caller-D");
        String familyId = pair.familyId();

        // Reproduce the exact state a late-but-overlapping loser observes: drive
        // the token through the same claim/publication protocol a winner uses,
        // with the rotation finishing "now" (inside the default 2000ms window).
        RefreshTokenRecord record = store.findRefreshToken(pair.refreshToken());
        assertEquals(RefreshTokenRecord.FirstTouch.WINNER,
                record.firstTouch(clock.nowMillis(), 2_000L), "the winner claims the token once");
        record.completeRotation(clock.nowMillis());

        AuthException ex = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-D"));
        assertEquals(AuthErrorCode.REFRESH_CONCURRENT_CONFLICT, ex.getErrorCode());
        assertEquals(Session.Status.ACTIVE, store.findSession(familyId).getStatus(),
                "a conflict inside the overlap window must leave the chain alive");
    }

    @Test
    @DisplayName("once the overlap window elapses, the same duplicate is a sequential replay that kills the chain")
    void afterOverlapWindowDuplicateIsSequentialReplay() {
        TokenPair pair = authService.login("dave2", "caller-D");
        String familyId = pair.familyId();
        RefreshTokenRecord record = store.findRefreshToken(pair.refreshToken());
        record.firstTouch(clock.nowMillis(), 2_000L);
        record.completeRotation(clock.nowMillis());

        clock.advanceMillis(2_001);
        AuthException ex = assertThrowsAuth(() -> authService.rotate(pair.refreshToken(), "caller-D"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, ex.getErrorCode());
        assertEquals(Session.Status.COMPROMISED, store.findSession(familyId).getStatus(),
                "a post-window reuse is the real replay that terminates the chain");
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
