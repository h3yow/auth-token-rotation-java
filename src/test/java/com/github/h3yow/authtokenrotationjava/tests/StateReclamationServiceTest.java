package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.maintenance.CleanupReport;
import com.github.h3yow.authtokenrotationjava.maintenance.StateReclamationService;
import com.github.h3yow.authtokenrotationjava.ratelimit.CallerRateLimiter;
import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitKey;
import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.service.TokenFactory;
import com.github.h3yow.authtokenrotationjava.store.InMemoryTokenStore;
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
 * Tests for controlled state reclamation: terminal/expired data is removed,
 * live data is never removed, the exact-expiry boundary is treated as dead,
 * and a sweep is safe to run concurrently with live traffic.
 */
class StateReclamationServiceTest {

    private MutableClock clock;
    private InMemoryTokenStore store;
    private AuthService authService;
    private CallerRateLimiter rateLimiter;
    private StateReclamationService reclamation;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setAccessTokenTtlMillis(300_000);
        properties.setRefreshTokenTtlMillis(3_600_000);
        store = new InMemoryTokenStore();
        rateLimiter = new CallerRateLimiter(properties, clock);
        authService = new AuthService(store, new TokenFactory(), properties, clock);
        reclamation = new StateReclamationService(store, rateLimiter, clock);
    }

    @Test
    @DisplayName("logged-out and compromised families are fully reclaimed; live families untouched")
    void terminalFamiliesReclaimedLiveKept() {
        TokenPair loggedOut = authService.login("alice", "caller-A");
        TokenPair compromised = authService.login("bob", "caller-B");

        authService.logout(loggedOut.refreshToken(), "caller-A");

        // Drive bob to a COMPROMISED chain via a genuine post-round replay.
        TokenPair rotated = authService.rotate(compromised.refreshToken(), "caller-B");
        clock.advanceMillis(30_001);
        assertThrowsAuth(() -> authService.rotate(compromised.refreshToken(), "caller-B"));

        // carol is born after all the destructive activity and stays ACTIVE.
        TokenPair alive = authService.login("carol", "caller-C");

        CleanupReport report = reclamation.purgeNow();
        assertNotNull(report);
        assertEquals(2, report.removedByCategory().get(StateReclamationService.CAT_SESSION_TERMINAL),
                "one logged-out + one compromised family removed");
        assertNull(store.findSession(loggedOut.familyId()), "logged-out session gone");
        assertNull(store.findSession(compromised.familyId()), "compromised session gone");
        assertNull(store.findRefreshToken(rotated.refreshToken()), "successor token removed with family");

        Session stillAlive = store.findSession(alive.familyId());
        assertNotNull(stillAlive);
        assertEquals(Session.Status.ACTIVE, stillAlive.getStatus());
        assertTrue(authService.verifyAccessToken(alive.accessToken(), "caller-C").accepted(),
                "a live session is never reclaimed");
        System.out.printf("[reclamation] terminal=2 live=1 retained report=%s%n", report.removedByCategory());
    }

    @Test
    @DisplayName("an ACTIVE family whose every token naturally expired is reclaimed")
    void naturallyExpiredFamilyReclaimed() {
        TokenPair pair = authService.login("dave", "caller-D");
        clock.advanceMillis(3_600_001); // both refresh (60m) and access (5m) expired
        CleanupReport report = reclamation.purgeNow();
        assertEquals(1, report.removedByCategory().get(StateReclamationService.CAT_SESSION_EXPIRED));
        assertNull(store.findSession(pair.familyId()));
        assertNull(store.findRefreshToken(pair.refreshToken()));
        assertNull(store.findAccessToken(pair.accessToken()));
        System.out.printf("[reclamation] all-expired family removed report=%s%n", report.removedByCategory());
    }

    @Test
    @DisplayName("a family with any still-valid credential is retained even if another credential expired")
    void partiallyExpiredFamilyRetained() {
        TokenPair pair = authService.login("erin", "caller-E");
        clock.advanceMillis(300_001); // access expired, but refresh is still valid
        CleanupReport report = reclamation.purgeNow();
        assertNull(report.removedByCategory().get(StateReclamationService.CAT_SESSION_EXPIRED),
                "refresh still live => family retained");
        assertNotNull(store.findSession(pair.familyId()));
        // And the retained family can still rotate via its live refresh token.
        TokenPair next = authService.rotate(pair.refreshToken(), "caller-E");
        assertTrue(authService.verifyAccessToken(next.accessToken(), "caller-E").accepted());
        System.out.println("[reclamation] partially expired (access dead, refresh live) retained");
    }

    @Test
    @DisplayName("exact-expiry boundary: a token expiring exactly at the sweep instant is dead and reclaimed")
    void exactExpiryBoundaryIsReclaimed() {
        TokenPair pair = authService.login("frank", "caller-F");
        // Advance so the access token expires at exactly the sweep instant
        // (access TTL 300000). The refresh token is still live, so the family
        // must still be retained; then age the refresh to its exact boundary.
        clock.advanceMillis(300_000);
        assertEquals(AuthErrorCode.ACCESS_TOKEN_EXPIRED.code(),
                authService.verifyAccessToken(pair.accessToken(), "caller-F").reason(),
                "expiresAt == now is already expired (boundary inclusive)");

        clock.advanceMillis(3_300_000); // total 3_600_000 == refresh expiresAt exactly
        AccessVerification refreshTokenDeadCheck = authService.verifyAccessToken(pair.accessToken(), "caller-F");
        assertEquals(AuthErrorCode.ACCESS_TOKEN_EXPIRED.code(), refreshTokenDeadCheck.reason());
        CleanupReport report = reclamation.purgeNow();
        assertEquals(1, report.removedByCategory().get(StateReclamationService.CAT_SESSION_EXPIRED),
                "a credential at its exact expiry instant is treated as expired");
        assertNull(store.findSession(pair.familyId()));
        System.out.printf("[reclamation] exact-expiry boundary reclaimed report=%s%n",
                report.removedByCategory());
    }

    @Test
    @DisplayName("one millisecond before expiry the family is retained; one millisecond later it is reclaimed")
    void expiryBoundaryOneMillisecondEitherSide() {
        TokenPair pair = authService.login("grace", "caller-G");
        clock.advanceMillis(3_599_999); // one ms before refresh expiry
        CleanupReport retained = reclamation.purgeNow();
        assertNotNull(store.findSession(pair.familyId()), "one ms before expiry: retained");
        assertNull(retained.removedByCategory().get(StateReclamationService.CAT_SESSION_EXPIRED));

        clock.advanceMillis(1); // now exactly expired -> retained? exact boundary: expired
        // access already long expired; refresh expires at this instant -> reclaimed
        CleanupReport gone = reclamation.purgeNow();
        assertEquals(1, gone.removedByCategory().get(StateReclamationService.CAT_SESSION_EXPIRED));
        assertNull(store.findSession(pair.familyId()));
        System.out.println("[reclamation] boundary -1ms retained / at-expiry reclaimed");
    }

    @Test
    @DisplayName("purge running concurrently with rotations and accesses never deletes a live family")
    void purgeConcurrentWithTrafficKeepsLiveFamilies() throws Exception {
        int families = 20;
        TokenPair[] roots = new TokenPair[families];
        for (int i = 0; i < families; i++) {
            roots[i] = authService.login("subject-" + i, "caller-" + i);
        }

        int sweeperThreads = 3;
        int sweepsPerThread = 20;
        ExecutorService pool = Executors.newFixedThreadPool(sweeperThreads + 1);
        CountDownLatch ready = new CountDownLatch(sweeperThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger sweepsRun = new AtomicInteger();
        AtomicInteger rotationFailures = new AtomicInteger();

        // Traffic thread: continuously rotate every family and verify the new
        // access token. The logical clock never advances, so every credential
        // stays valid; any negative verdict could only come from reclamation
        // wrongly deleting live state.
        pool.submit(() -> {
            try {
                ready.countDown();
                start.await();
                for (int round = 0; round < 60; round++) {
                    int idx = round % families;
                    try {
                        TokenPair next = authService.rotate(roots[idx].refreshToken(), "caller-" + idx);
                        AccessVerification v = authService.verifyAccessToken(next.accessToken(), "caller-" + idx);
                        if (!v.accepted()) {
                            rotationFailures.incrementAndGet();
                        }
                        roots[idx] = next;
                    } catch (AuthException ex) {
                        rotationFailures.incrementAndGet();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        for (int t = 0; t < sweeperThreads; t++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    for (int i = 0; i < sweepsPerThread; i++) {
                        CleanupReport r = reclamation.purgeNow();
                        if (r != null) {
                            sweepsRun.incrementAndGet();
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

        System.out.printf("[reclamation-concurrency] families=%d sweepsRun=%d rotationFailures=%d%n",
                families, sweepsRun.get(), rotationFailures.get());
        assertEquals(0, rotationFailures.get(), "no live family may be deleted under concurrent purge");
        for (int i = 0; i < families; i++) {
            assertNotNull(store.findSession(roots[i].familyId()),
                    "family " + i + " actively rotated must survive every sweep");
            assertTrue(authService.verifyAccessToken(roots[i].accessToken(), "caller-" + i).accepted(),
                    "latest access token of family " + i + " remains valid");
        }
    }

    @Test
    @DisplayName("idle rate-limit keys are reclaimed once their window empties")
    void idleRateLimitKeysReclaimed() {
        rateLimiter.checkAndRegister(RateLimitKey.authenticated("caller-IDLE"));
        rateLimiter.checkAndRegister(RateLimitKey.issuance("issuer-IDLE"));
        // Still inside the window: nothing reclaimed.
        assertEquals(0, rateLimiter.purgeIdleKeys(clock.nowMillis()));
        // After the window ages out, both idle keys and their lock objects go.
        int removed = rateLimiter.purgeIdleKeys(clock.nowMillis() + 1_001);
        assertEquals(2, removed);
        System.out.println("[reclamation] idle rate-limit keys removed=2");
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
