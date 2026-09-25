package com.github.h3yow.authtokenrotationjava.domain;

/**
 * Immutable result of verifying an access token. The {@code accepted} flag and
 * the stable {@code reason} code let callers and tests distinguish every
 * possible decision.
 */
public record AccessVerification(
        boolean accepted,
        String reason,
        String callerId,
        String subject,
        String familyId,
        String tokenId,
        String tokenState) {

    public static AccessVerification rejected(String reason, String callerId, String tokenId, String tokenState) {
        return new AccessVerification(false, reason, callerId, null, null, tokenId, tokenState);
    }
}
