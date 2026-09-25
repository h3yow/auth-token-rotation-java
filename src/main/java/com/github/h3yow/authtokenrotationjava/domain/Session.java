package com.github.h3yow.authtokenrotationjava.domain;

/**
 * A login session. All tokens issued from one login share the same
 * {@code familyId} and form a single rotation chain. A session is revoked
 * atomically, which propagates immediately to every token in the chain.
 */
public class Session {

    /** Why the whole rotation chain was invalidated. */
    public enum Status {
        ACTIVE,
        LOGGED_OUT,
        COMPROMISED
    }

    private final String familyId;
    private final String subject;
    private final String callerId;
    private final long createdAtMillis;
    private volatile Status status;
    private volatile long revokedAtMillis;
    private volatile String revocationReason;

    public Session(String familyId, String subject, String callerId, long createdAtMillis) {
        this.familyId = familyId;
        this.subject = subject;
        this.callerId = callerId;
        this.createdAtMillis = createdAtMillis;
        this.status = Status.ACTIVE;
    }

    public String getFamilyId() {
        return familyId;
    }

    public String getSubject() {
        return subject;
    }

    public String getCallerId() {
        return callerId;
    }

    public long getCreatedAtMillis() {
        return createdAtMillis;
    }

    public Status getStatus() {
        return status;
    }

    public long getRevokedAtMillis() {
        return revokedAtMillis;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    /**
     * Move the chain to a terminal status. The first revocation wins; a later
     * revocation never overwrites it, which keeps the decision basis stable
     * (a logout can never hide a replay verdict, and vice versa).
     */
    public synchronized void revoke(Status terminal, long atMillis, String reason) {
        if (this.status == Status.ACTIVE && terminal != Status.ACTIVE) {
            this.status = terminal;
            this.revokedAtMillis = atMillis;
            this.revocationReason = reason;
        }
    }
}
