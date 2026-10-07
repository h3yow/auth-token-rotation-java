package com.github.h3yow.authtokenrotationjava.domain;

/** Server-side state of a single refresh token in a rotation chain. */
public class RefreshTokenRecord {

    /** Lifecycle state of one refresh token. */
    public enum State {
        ACTIVE,
        ROTATED,
        REVOKED
    }

    private final String tokenId;
    private final String familyId;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private volatile State state;
    private volatile long rotatedAtMillis;
    private volatile String successorRefreshToken;

    public RefreshTokenRecord(String tokenId, String familyId, long issuedAtMillis, long expiresAtMillis) {
        this.tokenId = tokenId;
        this.familyId = familyId;
        this.issuedAtMillis = issuedAtMillis;
        this.expiresAtMillis = expiresAtMillis;
        this.state = State.ACTIVE;
    }

    public String getTokenId() {
        return tokenId;
    }

    public String getFamilyId() {
        return familyId;
    }

    public long getIssuedAtMillis() {
        return issuedAtMillis;
    }

    public long getExpiresAtMillis() {
        return expiresAtMillis;
    }

    public State getState() {
        return state;
    }

    public long getRotatedAtMillis() {
        return rotatedAtMillis;
    }

    /**
     * The new refresh token that replaced this one during the successful
     * rotation. Null until the token has been rotated. The successor's live
     * state is what distinguishes a benign concurrent conflict (successor
     * still ACTIVE) from a sequential replay (successor already consumed).
     */
    public String getSuccessorRefreshToken() {
        return successorRefreshToken;
    }

    /**
     * Mark this token as legitimately consumed by a successful rotation and
     * remember its successor. Returns true only for the first caller, giving
     * an atomic one-shot transition even though the surrounding store lock
     * serializes callers.
     */
    public synchronized boolean markRotated(long atMillis, String newSuccessorRefreshToken) {
        if (state != State.ACTIVE) {
            return false;
        }
        state = State.ROTATED;
        rotatedAtMillis = atMillis;
        successorRefreshToken = newSuccessorRefreshToken;
        return true;
    }

    /** Terminal revocation (chain logout or replay detection). */
    public synchronized void markRevoked() {
        if (state != State.REVOKED) {
            state = State.REVOKED;
        }
    }
}
