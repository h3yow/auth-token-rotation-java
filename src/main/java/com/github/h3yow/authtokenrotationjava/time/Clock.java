package com.github.h3yow.authtokenrotationjava.time;

/**
 * Abstraction over the current time so token expiry and rate-limit windows
 * can be driven deterministically in tests.
 */
public interface Clock {
    /** Current epoch milliseconds. */
    long nowMillis();
}
