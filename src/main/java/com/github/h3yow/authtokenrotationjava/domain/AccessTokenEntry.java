package com.github.h3yow.authtokenrotationjava.domain;

import java.time.Instant;

/**
 * 访问令牌的服务端状态。访问令牌与其所属刷新链路（会话）绑定。
 */
public final class AccessTokenEntry {

    private final String tokenId;
    private final String familyId;
    private final String clientId;
    private final String username;
    private final Instant expiresAt;
    private final Instant issuedAt;
    private volatile boolean revoked;

    public AccessTokenEntry(String tokenId, String familyId, String clientId,
                            String username, Instant issuedAt, Instant expiresAt) {
        this.tokenId = tokenId;
        this.familyId = familyId;
        this.clientId = clientId;
        this.username = username;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.revoked = false;
    }

    public String getTokenId() { return tokenId; }
    public String getFamilyId() { return familyId; }
    public String getClientId() { return clientId; }
    public String getUsername() { return username; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void markRevoked() { this.revoked = true; }
}
