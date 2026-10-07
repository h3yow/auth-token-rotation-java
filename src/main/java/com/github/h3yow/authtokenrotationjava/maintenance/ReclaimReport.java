package com.github.h3yow.authtokenrotationjava.maintenance;

/**
 * Observable result of one reclamation sweep: how many records of each category
 * were removed. A {@code scanned} count accompanies every {@code removed} count
 * so operators can judge whether a policy is actually doing anything.
 */
public record ReclaimReport(
        long atMillis,
        long sessionsScanned,
        long terminalSessionsRemoved,
        long refreshTokensScanned,
        long terminalRefreshTokensRemoved,
        long expiredRefreshTokensRemoved,
        long accessTokensScanned,
        long terminalAccessTokensRemoved,
        long expiredAccessTokensRemoved,
        long totalRemoved) {

    public static ReclaimReport empty(long atMillis) {
        return new ReclaimReport(atMillis, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
