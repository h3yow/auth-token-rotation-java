package com.github.h3yow.authtokenrotationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tunable security parameters. Bound from properties prefixed with
 * {@code auth.security}.
 */
@ConfigurationProperties(prefix = "auth.security")
public class SecurityProperties {

    /** Lifetime of an access token in milliseconds. */
    private long accessTokenTtlMillis = 5 * 60 * 1000L;

    /** Lifetime of a refresh token in milliseconds. */
    private long refreshTokenTtlMillis = 60 * 60 * 1000L;

    /** Maximum number of accepted requests per caller inside one window. */
    private int rateLimitMaxRequests = 5;

    /** Length of the sliding rate-limit window in milliseconds. */
    private long rateLimitWindowMillis = 1000L;

    /**
     * Grace window after a successful rotation during which a reuse of the
     * consumed refresh token is classified as a benign concurrent conflict
     * (HTTP 409) instead of a sequential replay. This makes the verdict for a
     * batch of concurrent retries independent of thread scheduling.
     */
    private long refreshConcurrentGraceMillis = 30_000L;

    public long getAccessTokenTtlMillis() {
        return accessTokenTtlMillis;
    }

    public void setAccessTokenTtlMillis(long accessTokenTtlMillis) {
        this.accessTokenTtlMillis = accessTokenTtlMillis;
    }

    public long getRefreshTokenTtlMillis() {
        return refreshTokenTtlMillis;
    }

    public void setRefreshTokenTtlMillis(long refreshTokenTtlMillis) {
        this.refreshTokenTtlMillis = refreshTokenTtlMillis;
    }

    public int getRateLimitMaxRequests() {
        return rateLimitMaxRequests;
    }

    public void setRateLimitMaxRequests(int rateLimitMaxRequests) {
        this.rateLimitMaxRequests = rateLimitMaxRequests;
    }

    public long getRateLimitWindowMillis() {
        return rateLimitWindowMillis;
    }

    public void setRateLimitWindowMillis(long rateLimitWindowMillis) {
        this.rateLimitWindowMillis = rateLimitWindowMillis;
    }

    public long getRefreshConcurrentGraceMillis() {
        return refreshConcurrentGraceMillis;
    }

    public void setRefreshConcurrentGraceMillis(long refreshConcurrentGraceMillis) {
        this.refreshConcurrentGraceMillis = refreshConcurrentGraceMillis;
    }
}
