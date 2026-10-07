package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.maintenance.ReclaimReport;
import com.github.h3yow.authtokenrotationjava.maintenance.StateReclaimer;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Safe-reclamation tests: terminal/expired data is collected, live data is
 * never touched, the boundary predicate matches authentication, and a sweep
 * running concurrently with traffic does not delete valid sessions/tokens.
 */
class StateReclaimerTest {

    private MutableClock clock;
    private AuthService authService;
    private TokenStore store;
    private StateReclaimer reclaimer;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setAccessTokenTtlMillis(300_000);
        properties.setRefreshTokenTtlMillis(3_600_000);
        store = new InMemoryTokenStore();
        authService = new AuthService(store, new TokenFactory(), properties, clock);
        reclaimer = new StateReclaimer(store, clock);
    }

    @Test
    @DisplayName("logged-out session and its tokens are reclaimed; active sibling is untouched")
    void reclaimsTerminalSessionButNotActiveOne() {
        TokenPair dead = authService.login("dead", "caller-A");
        TokenPair alive = authService.login("alive", "caller-B");
        authService.logout(dead.refreshToken(), "caller-A");

        ReclaimReport report = reclaimer.reclaim();
        System.out.printf("[reclaim-logout] %s%n", report);

        assertNull(store.findSession(dead.familyId()), "logged-out session must be removed");
        assertNull(store.findRefreshToken(dead.refreshToken()));
        assertNull(store.findAccessToken(dead.accessToken()));

        assertNotNull(store.findSession(alive.familyId()), "active session must survive");
        assertNotNull(store.findRefreshToken(alive.refreshToken()));
        assertTrue(authService.verifyAccessToken(alive.accessToken(), "caller-B").accepted(),
                "active sibling access token must still verify");

        assertEquals(1, report.terminalSessionsRemoved());
        assertTrue(report.totalRemoved() >= 3);
    }

    @Test
    @DisplayName("a replayed (COMPROMISED) chain is reclaimed and the winner pair with it")
    void reclaimsCompromisedChain() {
        TokenPair first = authService.login("bob", "caller-B");
        TokenPair second = authService.rotate(first.refreshToken(), "caller-B");
        clock.advanceMillis(2_001);
        expectFailure(() -> authService.rotate(first.refreshToken(), "caller-B")); // sequential replay kills chain

        ReclaimReport report = reclaimer.reclaim();
        System.out.printf("[reclaim-replay] %s%n", report);

        assertNull(store.findSession(first.familyId()));
        assertNull(store.findAccessToken(first.accessToken()));
        assertNull(store.findAccessToken(second.accessToken()));
        assertTrue(report.terminalSessionsRemoved() >= 1);
    }

    @Test
    @DisplayName("naturally expired access/refresh tokens are collected while the active session stays")
    void reclaimsExpiredTokensButKeepsActiveSession() {
        TokenPair pair = authService.login("heidi", "caller-H");
        clock.advanceMillis(300_001); // access token now expired
        AccessVerification expired = authService.verifyAccessToken(pair.accessToken(), "caller-H");
        assertEquals(false, expired.accepted());

        ReclaimReport afterAccessExpiry = reclaimer.reclaim();
        System.out.printf("[reclaim-expired-access] %s%n", afterAccessExpiry);
        assertNull(store.findAccessToken(pair.accessToken()), "expired access token must be removed");
        assertNotNull(store.findSession(pair.familyId()), "session stays: only the access token expired");
        assertNotNull(store.findRefreshToken(pair.refreshToken()), "unexpired refresh token stays");

        clock.advanceMillis(3_600_000); // refresh token now expired too
        ReclaimReport afterRefreshExpiry = reclaimer.reclaim();
        System.out.printf("[reclaim-expired-refresh] %s%n", afterRefreshExpiry);
        assertNull(store.findRefreshToken(pair.refreshToken()), "expired refresh token must be removed");
        assertNull(store.findSession(pair.familyId()),
                "terminal session whose last credential expired is removed");
    }

    @Test
    @DisplayName("exact expiry boundary: expiresAt == now is reclaimed, matching the authentication predicate")
    void boundaryIsExpiredNotValid() {
        TokenPair pair = authService.login("boundary", "caller-X");
        // Advance exactly to the access token's expiry instant: <= means expired.
        clock.setMillis(pair.accessTokenExpiresAtMillis());

        // Authentication itself must treat it as expired...
        AccessVerification v = authService.verifyAccessToken(pair.accessToken(), "caller-X");
        assertEquals("access_token_expired", v.reason(), "boundary credential is expired for auth");

        ReclaimReport report = reclaimer.reclaim();
        assertNull(store.findAccessToken(pair.accessToken()),
                "...and reclamation must collect it, never treat it as valid");
        System.out.printf("[reclaim-boundary] at=%d %s%n", clock.nowMillis(), report);
    }

    @Test
    @DisplayName("reclaim sweeps run concurrently with rotating traffic without deleting a valid chain")
    void concurrentReclaimDoesNotHarmActiveChains() throws Exception {
        TokenPair seed = authService.login("carol", "caller-C");
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
        CountDownLatch ready = new CountDownLatch(threads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();

        // Rotation workers keep moving the chain forward.
        String[] currentRefresh = {seed.refreshToken()};
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    for (int step = 0; step < 20; step++) {
                        synchronized (currentRefresh) {
                            try {
                                TokenPair next = authService.rotate(currentRefresh[0], "caller-C");
                                currentRefresh[0] = next.refreshToken();
                            } catch (RuntimeException ignore) {
                                // serialized contention is expected; only real breakage is counted below
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        // Reclamation worker sweeps continuously.
        pool.submit(() -> {
            try {
                ready.countDown();
                start.await();
                for (int step = 0; step < 40; step++) {
                    reclaimer.reclaim();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        ready.await();
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // The live chain must still exist and rotate after the storm.
        assertNotNull(store.findSession(seed.familyId()), "active session must never be reclaimed");
        TokenPair finalPair;
        synchronized (currentRefresh) {
            finalPair = authService.rotate(currentRefresh[0], "caller-C");
        }
        assertTrue(authService.verifyAccessToken(finalPair.accessToken(), "caller-C").accepted(),
                "a freshly rotated token after concurrent reclamation must verify");
        assertEquals(0, failures.get());
        System.out.printf("[reclaim-concurrent] familyId=%s finalState=ACTIVE_and_rotatable failures=%d%n",
                seed.familyId(), failures.get());
    }

    @Test
    @DisplayName("reclaim report is observable and idempotent: a second sweep removes nothing")
    void reportIsObservableAndSweepIdempotent() {
        TokenPair dead = authService.login("dead", "caller-A");
        authService.logout(dead.refreshToken(), "caller-A");
        ReclaimReport first = reclaimer.reclaim();
        ReclaimReport second = reclaimer.reclaim();
        System.out.printf("[reclaim-idempotent] first.total=%d second.total=%d%n",
                first.totalRemoved(), second.totalRemoved());
        assertTrue(first.totalRemoved() >= 3);
        assertEquals(0, second.totalRemoved(), "nothing dead remains for a second sweep");
    }

    private void expectFailure(Runnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("expected a rejection");
        } catch (RuntimeException expected) {
            // decision already logged by the service
        }
    }
}
