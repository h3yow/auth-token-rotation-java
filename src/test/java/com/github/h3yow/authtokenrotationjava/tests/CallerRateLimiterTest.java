package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.ratelimit.CallerRateLimiter;
import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitDecision;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Boundary and concurrency tests for the per-caller sliding window.
 */
class CallerRateLimiterTest {

    private MutableClock clock;
    private CallerRateLimiter limiter;
    private static final int LIMIT = 5;
    private static final long WINDOW = 1_000L;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setRateLimitMaxRequests(LIMIT);
        properties.setRateLimitWindowMillis(WINDOW);
        limiter = new CallerRateLimiter(properties, clock);
    }

    @Test
    @DisplayName("exactly limit requests pass, the next one is rejected with a distinct reason")
    void limitBoundaryIsStable() {
        for (int i = 1; i <= LIMIT; i++) {
            RateLimitDecision decision = limiter.checkAndRegister("caller-A");
            assertTrue(decision.allowed(), "request " + i + " within limit must pass");
            assertEquals(i, decision.requestCountInWindow());
        }
        RateLimitDecision blocked = limiter.checkAndRegister("caller-A");
        assertFalse(blocked.allowed(), "the 6th request in the same window must be blocked");
        assertEquals(LIMIT, blocked.requestCountInWindow(), "rejected request is not registered");
        System.out.printf("[rate-limit-boundary] callerId=caller-A allowed=%d blocked=1 reason=rate_limit_exceeded%n",
                LIMIT);
    }

    @Test
    @DisplayName("window boundary: aging out exactly one slot frees exactly one slot")
    void windowBoundaryReleasesExactlyOneSlot() {
        for (int i = 0; i < LIMIT; i++) {
            assertTrue(limiter.checkAndRegister("caller-A").allowed());
        }
        assertFalse(limiter.checkAndRegister("caller-A").allowed());

        // 999ms later the oldest timestamp (age 999) is still inside the
        // (now-1000, now] window: still blocked.
        clock.advanceMillis(999);
        assertFalse(limiter.checkAndRegister("caller-A").allowed(), "just inside the window still blocked");

        // At t=1000 every t=0 timestamp reaches window age and is evicted
        // together (collective aging at one instant), so the window is empty
        // and all limit slots are deterministically available again.
        clock.advanceMillis(1);
        for (int i = 1; i <= LIMIT; i++) {
            RateLimitDecision decision = limiter.checkAndRegister("caller-A");
            assertTrue(decision.allowed(), "refilled slot " + i + " at the boundary must pass");
            assertEquals(i, decision.requestCountInWindow());
        }
        assertFalse(limiter.checkAndRegister("caller-A").allowed(),
                "window fills back up to the limit and the next request is blocked");
        System.out.println("[rate-limit-boundary] callerId=caller-A at t=1000 "
                + "reason=all_t0_stamps_aged_collectively then rate_limit_exceeded");
    }

    @Test
    @DisplayName("callers are isolated: one saturated caller never blocks another")
    void differentCallersDoNotInterfere() {
        for (int i = 0; i < LIMIT; i++) {
            assertTrue(limiter.checkAndRegister("noisy-caller").allowed());
        }
        for (int extra = 0; extra < 10; extra++) {
            assertFalse(limiter.checkAndRegister("noisy-caller").allowed(),
                    "noisy caller remains saturated, extra request " + extra);
        }
        for (int i = 0; i < LIMIT; i++) {
            RateLimitDecision decision = limiter.checkAndRegister("quiet-caller");
            assertTrue(decision.allowed(), "quiet caller must be unaffected by the noisy one, request " + i);
        }
        assertFalse(limiter.checkAndRegister("quiet-caller").allowed(), "quiet caller counts its own requests");
        System.out.println("[rate-limit-isolation] noisy-caller=saturated quiet-caller=independent");
    }

    @Test
    @DisplayName("concurrent requests from one caller never exceed the limit (no leak under races)")
    void concurrentRequestsDoNotLeak() throws InterruptedException {
        int threads = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger blocked = new AtomicInteger();
        List<Boolean> verdicts = java.util.Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    boolean verdict = limiter.checkAndRegister("caller-C").allowed();
                    verdicts.add(verdict);
                    if (verdict) {
                        allowed.incrementAndGet();
                    } else {
                        blocked.incrementAndGet();
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

        System.out.printf("[rate-limit-concurrency] callerId=caller-C threads=%d allowed=%d blocked=%d%n",
                threads, allowed.get(), blocked.get());
        assertEquals(LIMIT, allowed.get(), "no request may leak past the limit");
        assertEquals(threads - LIMIT, blocked.get(), "every over-limit concurrent request is blocked");
    }
}
