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
     * Mark this token as legitimately consumed by a successful rotation.
     * Returns true only for the first caller, giving an atomic one-shot
     * transition even though the surrounding store lock serializes callers.
     */
    public synchronized boolean markRotated(long atMillis) {
        if (state != State.ACTIVE) {
            return false;
        }
        state = State.ROTATED;
        rotatedAtMillis = atMillis;
        return true;
    }

    /** Terminal revocation (chain logout or replay detection). */
    public synchronized void markRevoked() {
        if (state != State.REVOKED) {
            state = State.REVOKED;
        }
    }
}
