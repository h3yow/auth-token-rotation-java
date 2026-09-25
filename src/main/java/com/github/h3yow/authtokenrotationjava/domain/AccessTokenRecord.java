package com.github.h3yow.authtokenrotationjava.domain;

/** Server-side state of a single access token. */
public class AccessTokenRecord {

    private final String tokenId;
    private final String familyId;
    private final String subject;
    private final String callerId;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private volatile boolean revoked;

    public AccessTokenRecord(String tokenId, String familyId, String subject, String callerId,
                             long issuedAtMillis, long expiresAtMillis) {
        this.tokenId = tokenId;
        this.familyId = familyId;
        this.subject = subject;
        this.callerId = callerId;
        this.issuedAtMillis = issuedAtMillis;
        this.expiresAtMillis = expiresAtMillis;
    }

    public String getTokenId() {
        return tokenId;
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

    public long getIssuedAtMillis() {
        return issuedAtMillis;
    }

    public long getExpiresAtMillis() {
        return expiresAtMillis;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public synchronized void markRevoked() {
        this.revoked = true;
    }
}
