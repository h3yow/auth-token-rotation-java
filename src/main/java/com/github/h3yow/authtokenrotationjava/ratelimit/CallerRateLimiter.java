package com.github.h3yow.authtokenrotationjava.ratelimit;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.time.Clock;
import org.springframework.stereotype.Component;

import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Per-caller sliding-window rate limiter. Keys are caller identities only, so
 * callers are isolated from each other. The probe is atomic per key, which
 * keeps concurrent requests and window boundaries deterministic.
 */
@Component
public class CallerRateLimiter {

    private final SecurityProperties properties;
    private final Clock clock;
    private final ConcurrentMap<String, Object> keyLocks = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Deque<Long>> requestLogs = new ConcurrentHashMap<>();

    public CallerRateLimiter(SecurityProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Register one request from {@code callerId} and decide whether it is
     * allowed under the current sliding window. Eviction, counting and
     * insertion happen atomically under the caller's own lock, so:
     * <ul>
     *   <li>the first {@code maxRequests} requests in a window are accepted;</li>
     *   <li>the next request is rejected until an earlier request ages out;</li>
     *   <li>a request exactly {@code windowMillis} after the oldest one is a
     *       new-window request (boundary inclusive), no leak, no误伤;</li>
     *   <li>different caller keys have different locks and logs.</li>
     * </ul>
     */
    public RateLimitDecision checkAndRegister(String callerId) {
        long window = properties.getRateLimitWindowMillis();
        int limit = properties.getRateLimitMaxRequests();
        long now = clock.nowMillis();
        long windowStart = now - window;

        synchronized (lockFor(callerId)) {
            Deque<Long> log = requestLogs.computeIfAbsent(callerId, key -> new ConcurrentLinkedDeque<>());
            // Evict timestamps that are strictly older than the window. A
            // request whose age equals the window length is evicted, so the
            // boundary behaves as a new window rather than being double-counted.
            while (!log.isEmpty() && log.peekFirst() <= windowStart) {
                log.pollFirst();
            }
            long count = log.size();
            boolean allowed = count < limit;
            if (allowed) {
                log.addLast(now);
                count = log.size();
            }
            long oldest = log.isEmpty() ? now : log.peekFirst();
            return new RateLimitDecision(allowed, callerId, count, oldest, oldest + window, limit, window);
        }
    }

    private Object lockFor(String callerId) {
        return keyLocks.computeIfAbsent(callerId, key -> new Object());
    }

    /** Test/ops helper: forget all callers. */
    public void reset() {
        keyLocks.clear();
        requestLogs.clear();
    }
}
