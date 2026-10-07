package com.github.h3yow.authtokenrotationjava.identity;

import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitKey;

/**
 * Server-side resolution of "who is making this request".
 *
 * @param trusted            whether a server-side credential confirmed the caller
 * @param declaredCallerId   raw value of the X-Caller-Id header (may be null)
 * @param confirmedCallerId  caller id proven by the credential, null if untrusted
 * @param rateLimitKey       bucket the request must be billed to, null if none
 * @param familyId           family implied by the credential, null if none
 * @param basis              short machine-readable reason explaining the resolution
 */
public record CallerIdentity(boolean trusted,
                             String declaredCallerId,
                             String confirmedCallerId,
                             RateLimitKey rateLimitKey,
                             String familyId,
                             String basis) {
}
