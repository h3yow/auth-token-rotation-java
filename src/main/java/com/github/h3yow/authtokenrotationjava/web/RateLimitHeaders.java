package com.github.h3yow.authtokenrotationjava.web;

/** Shared HTTP header name constants for the caller identity boundary. */
public final class RateLimitHeaders {

    /** Declared (and, after gating, server-attested) caller identity. */
    public static final String CALLER_HEADER = "X-Caller-Id";

    private RateLimitHeaders() {
    }
}
