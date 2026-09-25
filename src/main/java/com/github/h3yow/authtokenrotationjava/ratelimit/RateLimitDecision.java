package com.github.h3yow.authtokenrotationjava.ratelimit;

/** Result of one rate-limit probe. */
public record RateLimitDecision(
        boolean allowed,
        String callerId,
        long requestCountInWindow,
        long windowStartMillis,
        long windowEndMillis,
        long limit,
        long windowMillis) {
}
