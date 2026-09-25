package com.github.h3yow.authtokenrotationjava.service;

/**
 * Stable, machine-readable decision codes. Every rejected request maps to one
 * distinct code so test results remain explainable and reproducible.
 */
public enum AuthErrorCode {

    // access token verification
    ACCESS_TOKEN_MISSING("access_token_missing", 401),
    ACCESS_TOKEN_UNKNOWN("access_token_unknown", 401),
    ACCESS_TOKEN_EXPIRED("access_token_expired", 401),
    ACCESS_TOKEN_CALLER_MISMATCH("access_token_caller_mismatch", 401),
    ACCESS_TOKEN_REVOKED_LOGOUT("access_token_revoked_logout", 401),
    ACCESS_TOKEN_REVOKED_REPLAY("access_token_revoked_replay", 401),

    // refresh flow
    REFRESH_TOKEN_UNKNOWN("refresh_token_unknown", 401),
    REFRESH_TOKEN_EXPIRED("refresh_token_expired", 401),
    REFRESH_TOKEN_CALLER_MISMATCH("refresh_token_caller_mismatch", 401),
    REFRESH_TOKEN_REPLAY_SEQUENTIAL("refresh_token_replay_sequential", 401),
    REFRESH_TOKEN_REPLAY_CONCURRENT("refresh_token_replay_concurrent", 401),
    CHAIN_REVOKED_LOGOUT("chain_revoked_logout", 401),
    CHAIN_REVOKED_REPLAY("chain_revoked_replay", 401),

    // rate limiting
    CALLER_IDENTITY_MISSING("caller_identity_missing", 400),
    RATE_LIMIT_EXCEEDED("rate_limit_exceeded", 429);

    private final String code;
    private final int httpStatus;

    AuthErrorCode(String code, int httpStatus) {
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public String code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }

    /** Resolve a stable wire code (as found in {@link AccessVerification}) back to an enum. */
    public static AuthErrorCode valueOfCode(String code) {
        for (AuthErrorCode candidate : values()) {
            if (candidate.code.equals(code)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("unknown error code: " + code);
    }
}
