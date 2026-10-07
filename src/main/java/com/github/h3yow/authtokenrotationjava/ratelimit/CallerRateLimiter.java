package com.github.h3yow.authtokenrotationjava.ratelimit;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.time.Clock;
import org.springframework.stereotype.Component;

import java.util.Deque;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Sliding-window rate limiter. A request is billed to a {@link RateLimitKey}:
 * authenticated traffic lands in the credential owner's AUTHENTICATED bucket,
 * while the credential-less issuance endpoint uses isolated ISSUANCE buckets,
 * so a forged caller header can never consume a real caller's quota.
 *
 * <p>The probe is atomic per key, keeping concurrent requests and window
 * boundaries deterministic.
 */
@Component
public class CallerRateLimiter {

    private final SecurityProperties properties;
    private final Clock clock;
    private final ConcurrentMap<RateLimitKey, Object> keyLocks = new ConcurrentHashMap<>();
    private final ConcurrentMap<RateLimitKey, Deque<Long>> requestLogs = new ConcurrentHashMap<>();

    public CallerRateLimiter(SecurityProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** Backward-compatible probe: treats the raw id as an AUTHENTICATED key. */
    public RateLimitDecision checkAndRegister(String callerId) {
        return checkAndRegister(RateLimitKey.authenticated(callerId));
    }

    /**
     * Register one request for {@code key} and decide whether it is allowed
     * under the current sliding window. Eviction, counting and insertion happen
     * atomically under the key's own lock, so the first {@code maxRequests}
     * requests in a window are accepted, the next rejected until an earlier
     * request ages out, and different keys never interfere.
     */
    public RateLimitDecision checkAndRegister(RateLimitKey key) {
        long window = properties.getRateLimitWindowMillis();
        int limit = properties.getRateLimitMaxRequests();
        long now = clock.nowMillis();
        long windowStart = now - window;

        synchronized (lockFor(key)) {
            Deque<Long> log = requestLogs.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());
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
            return new RateLimitDecision(allowed, key.identity(), key.scope().name(),
                    count, oldest, oldest + window, limit, window);
        }
    }

    private Object lockFor(RateLimitKey key) {
        return keyLocks.computeIfAbsent(key, k -> new Object());
    }

    /**
     * Forget every key whose window contains no timestamps (its last request
     * aged out). Called by state reclamation so idle callers do not retain
     * maps and lock objects forever.
     *
     * @return number of keys removed
     */
    public int purgeIdleKeys(long nowMillis) {
        long window = properties.getRateLimitWindowMillis();
        Set<RateLimitKey> keys = Set.copyOf(requestLogs.keySet());
        int removed = 0;
        for (RateLimitKey key : keys) {
            synchronized (lockFor(key)) {
                Deque<Long> log = requestLogs.get(key);
                if (log != null) {
                    while (!log.isEmpty() && log.peekFirst() <= nowMillis - window) {
                        log.pollFirst();
                    }
                }
                if (log == null || log.isEmpty()) {
                    requestLogs.remove(key);
                    keyLocks.remove(key);
                    removed++;
                }
            }
        }
        return removed;
    }

    /** Test/ops helper: forget all callers. */
    public void reset() {
        keyLocks.clear();
        requestLogs.clear();
    }
}
