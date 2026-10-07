package com.github.h3yow.authtokenrotationjava.ratelimit;

/**
 * Namespace of a rate-limit bucket. Requests whose caller identity was
 * confirmed by a server-side credential are billed to the credential owner's
 * {@link #AUTHENTICATED} bucket; the credential-less issuance endpoint uses
 * isolated {@link #ISSUANCE} buckets keyed by the raw declared identity, so a
 * forged header can never consume a real caller's quota.
 */
public enum RateLimitScope {
    AUTHENTICATED,
    ISSUANCE
}
