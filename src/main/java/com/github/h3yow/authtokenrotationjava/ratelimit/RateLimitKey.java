package com.github.h3yow.authtokenrotationjava.ratelimit;

/**
 * The billing key for one rate-limit probe: a scope plus the identity inside
 * that scope. Two identities with the same name in different scopes never
 * share a window.
 */
public record RateLimitKey(RateLimitScope scope, String identity) {

    public static RateLimitKey authenticated(String callerId) {
        return new RateLimitKey(RateLimitScope.AUTHENTICATED, callerId);
    }

    public static RateLimitKey issuance(String declaredCallerId) {
        return new RateLimitKey(RateLimitScope.ISSUANCE, declaredCallerId);
    }
}
