package com.github.h3yow.authtokenrotationjava.ratelimit;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.time.Clock;
import org.springframework.stereotype.Component;

import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Sliding-window rate limiter with explicit <b>trust tiers</b>. The accounting
 * key is never taken blindly from a client-declared header: callers are first
 * placed in one of the tiers below, and only requests authenticated as owning a
 * real caller's credential can spend that caller's quota.
 * <ul>
 *   <li>{@link Tier#TRUSTED}: the server resolved the presented credential to a
 *       real caller; the quota key is that server-attested owner id.</li>
 *   <li>{@link Tier#UNAUTHENTICATED}: pre-credential entry points (login,
 *       reclaim ops). They share a synthetic key isolated from every real
 *       caller, so a flood against the login endpoint can never exhaust a real
 *       caller's quota.</li>
 *   <li>{@link Tier#UNTRUSTED}: a request presented a forged/invalid identity or
 *       credential. These share a separate synthetic key; again no real caller's
 *       quota is touched, and the flood is still bounded.</li>
 * </ul>
 * Synthetic keys live in reserved namespaces that real caller ids cannot
 * collide with. The probe stays atomic per key, so window boundaries and
 * concurrent verdicts remain deterministic.
 */
@Component
public class CallerRateLimiter {

    /** Trust tier deciding which quota bucket a request is accounted to. */
    public enum Tier {
        TRUSTED,
        UNAUTHENTICATED,
        UNTRUSTED
    }

    private static final String UNAUTHENTICATED_KEY = "\u0000unauthenticated";
    private static final String UNTRUSTED_KEY = "\u0000untrusted";

    private final SecurityProperties properties;
    private final Clock clock;
    private final ConcurrentMap<String, Object> keyLocks = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Deque<Long>> requestLogs = new ConcurrentHashMap<>();

    public CallerRateLimiter(SecurityProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Account one request under the given tier.
     *
     * @param attestedCallerId the server-attested owner id for
     *        {@link Tier#TRUSTED}; ignored for the synthetic tiers
     */
    public RateLimitDecision checkAndRegister(Tier tier, String attestedCallerId) {
        String key = switch (tier) {
            case TRUSTED -> attestedCallerId;
            case UNAUTHENTICATED -> UNAUTHENTICATED_KEY;
            case UNTRUSTED -> UNTRUSTED_KEY;
        };
        String reportedCallerId = tier == Tier.TRUSTED ? attestedCallerId : tier.name().toLowerCase();
        return probe(key, reportedCallerId);
    }

    /**
     * Backwards-compatible probe for a trusted caller key. New code should
     * prefer {@link #checkAndRegister(Tier, String)}.
     */
    public RateLimitDecision checkAndRegister(String callerId) {
        return probe(callerId, callerId);
    }

    private RateLimitDecision probe(String key, String reportedCallerId) {
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
            return new RateLimitDecision(allowed, reportedCallerId, count, oldest, oldest + window, limit, window);
        }
    }

    private Object lockFor(String callerId) {
        return keyLocks.computeIfAbsent(callerId, key -> new Object());
    }

    /**
     * Evict empty per-key state older than the window. Caller data is never
     * deleted while it can still influence a decision; only fully aged-out
     * (empty) logs and their locks are collected.
     */
    public int evictIdleState() {
        long cutoff = clock.nowMillis() - properties.getRateLimitWindowMillis();
        int evicted = 0;
        for (String key : new java.util.ArrayList<>(requestLogs.keySet())) {
            synchronized (lockFor(key)) {
                Deque<Long> log = requestLogs.get(key);
                if (log != null && (log.isEmpty() || log.peekLast() <= cutoff)) {
                    requestLogs.remove(key);
                    keyLocks.remove(key);
                    evicted++;
                }
            }
        }
        return evicted;
    }

    /** Test/ops helper: forget all callers. */
    public void reset() {
        keyLocks.clear();
        requestLogs.clear();
    }
}
