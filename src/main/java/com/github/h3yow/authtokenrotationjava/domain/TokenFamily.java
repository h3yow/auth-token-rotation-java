package com.github.h3yow.authtokenrotationjava.domain;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * 一条刷新令牌链路（与一个会话一一对应）。
 *
 * <p>轮换时旧令牌以原子方式失效；旧令牌在"并发宽限窗口"内再次出现视为
 * 并发竞争落败，超过窗口再次出现则判定为重放，整条链路撤销。</p>
 */
public final class TokenFamily {

    private final String familyId;
    private final String clientId;
    private final String username;
    private volatile String currentRefreshTokenId;
    private volatile String lastConsumedTokenId;
    private final Set<String> consumedTokenIds = new HashSet<>();
    private volatile Instant lastRotatedAt;
    private volatile Instant refreshExpiresAt;
    private volatile boolean revoked;
    private volatile Instant revokedAt;
    private volatile String revokeReason;

    public TokenFamily(String familyId, String clientId, String username,
                       String currentRefreshTokenId, Instant issuedAt, Instant refreshExpiresAt) {
        this.familyId = familyId;
        this.clientId = clientId;
        this.username = username;
        this.currentRefreshTokenId = currentRefreshTokenId;
        this.lastRotatedAt = issuedAt;
        this.refreshExpiresAt = refreshExpiresAt;
        this.revoked = false;
    }

    public String getFamilyId() { return familyId; }
    public String getClientId() { return clientId; }
    public String getUsername() { return username; }
    public String getCurrentRefreshTokenId() { return currentRefreshTokenId; }
    public String getLastConsumedTokenId() { return lastConsumedTokenId; }
    public Set<String> getConsumedTokenIds() { return consumedTokenIds; }
    public Instant getLastRotatedAt() { return lastRotatedAt; }
    public Instant getRefreshExpiresAt() { return refreshExpiresAt; }
    public boolean isRevoked() { return revoked; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevokeReason() { return revokeReason; }

    /**
     * 原子轮换：记录刚失效（被消费）的一代令牌，切换到新一代令牌。
     */
    public void rotate(String consumedTokenId, String newRefreshTokenId,
                       Instant rotatedAt, Instant newRefreshExpiresAt) {
        this.lastConsumedTokenId = consumedTokenId;
        this.currentRefreshTokenId = newRefreshTokenId;
        this.lastRotatedAt = rotatedAt;
        this.refreshExpiresAt = newRefreshExpiresAt;
    }

    public void revoke(Instant at, String reason) {
        this.revoked = true;
        this.revokedAt = at;
        this.revokeReason = reason;
    }
}
