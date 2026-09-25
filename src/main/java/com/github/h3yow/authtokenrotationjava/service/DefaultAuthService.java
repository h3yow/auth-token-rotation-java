package com.github.h3yow.authtokenrotationjava.service;

import com.github.h3yow.authtokenrotationjava.config.AuthProperties;
import com.github.h3yow.authtokenrotationjava.domain.AccessTokenEntry;
import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.domain.RotationOutcome;
import com.github.h3yow.authtokenrotationjava.domain.TokenFamily;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.security.AuthException;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * 默认鉴权服务：令牌签发、原子轮换、重放链路撤销、会话注销与访问鉴权。
 */
@Service
public class DefaultAuthService implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuthService.class);

    /** 演示用固定口令；真实系统应替换为凭据库/密码哈希校验。 */
    private static final String DEMO_PASSWORD = "password";

    private static final String ACCESS_PREFIX = "atk.";
    private static final String REFRESH_PREFIX = "rtk.";

    private final TokenStore tokenStore;
    private final Clock clock;
    private final AuthProperties properties;

    public DefaultAuthService(TokenStore tokenStore, Clock clock, AuthProperties properties) {
        this.tokenStore = tokenStore;
        this.clock = clock;
        this.properties = properties;
    }

    @Override
    public TokenPair issue(String clientId, String username, String password) {
        if (username == null || username.isBlank() || !DEMO_PASSWORD.equals(password)) {
            log.warn("签发拒绝 | clientId={} | username={} | 判定依据=用户名或密码错误", clientId, username);
            throw new AuthException(AuthErrorCode.LOGIN_INVALID);
        }
        Instant now = Instant.now(clock);
        String familyId = newId();
        String refreshTokenId = newId();
        String accessTokenId = newId();

        TokenFamily family = new TokenFamily(familyId, clientId, username,
                refreshTokenId, now, now.plus(properties.refreshTtl()));
        tokenStore.saveFamily(family);

        AccessTokenEntry access = new AccessTokenEntry(accessTokenId, familyId, clientId, username,
                now, now.plus(properties.accessTtl()));
        tokenStore.saveAccess(access);

        TokenPair pair = new TokenPair(
                ACCESS_PREFIX + familyId + "." + accessTokenId,
                REFRESH_PREFIX + familyId + "." + refreshTokenId,
                familyId,
                access.getExpiresAt(),
                family.getRefreshExpiresAt());

        log.info("令牌签发 | clientId={} | username={} | sessionId={} | accessTokenId={} | refreshTokenId={} | "
                        + "状态=新会话 | accessExpiresAt={} | refreshExpiresAt={}",
                clientId, username, familyId, accessTokenId, refreshTokenId,
                access.getExpiresAt(), family.getRefreshExpiresAt());
        return pair;
    }

    @Override
    public TokenPair rotate(String clientId, String refreshToken) {
        TokenParts parts = parseToken(refreshToken, REFRESH_PREFIX);
        String familyId = parts.familyId();
        String presentedId = parts.tokenId();
        Instant now = Instant.now(clock);
        long graceMillis = properties.replayGraceWindow().toMillis();

        RotationOutcome outcome = tokenStore.withFamilyLock(familyId, family -> {
            if (family.isRevoked()) {
                return RotationOutcome.Rejection.FAMILY_REVOKED;
            }
            if (!family.getClientId().equals(clientId)) {
                // 调用方身份与链路归属不符：不暴露链路存在，按未知令牌处理
                return RotationOutcome.Rejection.UNKNOWN;
            }
            if (!family.getRefreshExpiresAt().isAfter(now)) {
                return RotationOutcome.Rejection.REFRESH_EXPIRED;
            }
            if (presentedId.equals(family.getCurrentRefreshTokenId())) {
                // 唯一获胜路径：当前令牌原子失效，生成新令牌对
                String oldTokenId = family.getCurrentRefreshTokenId();
                family.getConsumedTokenIds().add(oldTokenId);

                String newRefreshTokenId = newId();
                String newAccessTokenId = newId();
                Instant newRefreshExpiresAt = now.plus(properties.refreshTtl());
                family.rotate(oldTokenId, newRefreshTokenId, now, newRefreshExpiresAt);

                AccessTokenEntry newAccess = new AccessTokenEntry(newAccessTokenId, familyId,
                        family.getClientId(), family.getUsername(), now,
                        now.plus(properties.accessTtl()));
                tokenStore.saveAccess(newAccess);

                TokenPair pair = new TokenPair(
                        ACCESS_PREFIX + familyId + "." + newAccessTokenId,
                        REFRESH_PREFIX + familyId + "." + newRefreshTokenId,
                        familyId, newAccess.getExpiresAt(), newRefreshExpiresAt);
                log.info("刷新成功（轮换） | clientId={} | sessionId={} | 旧refreshTokenId={} | 新refreshTokenId={} | "
                                + "新accessTokenId={} | 判定依据=当前刷新令牌，原子轮换",
                        clientId, familyId, oldTokenId, newRefreshTokenId, newAccessTokenId);
                return new RotationOutcome.Rotated(pair, oldTokenId);
            }
            if (family.getConsumedTokenIds().contains(presentedId)) {
                long ageMillis = Duration.between(family.getLastRotatedAt(), now).toMillis();
                boolean isLatestConsumedGeneration = presentedId.equals(family.getLastConsumedTokenId());
                if (isLatestConsumedGeneration && ageMillis <= graceMillis) {
                    // 最近一次轮换刚失效的那一代令牌在宽限窗口内被再次使用：
                    // 这是同一令牌的并发/即时重复提交，竞争落败；不撤销链路，不影响合法会话。
                    log.warn("刷新拒绝（并发竞争落败） | clientId={} | sessionId={} | 竞争refreshTokenId={} | "
                                    + "距上次轮换={}ms | 宽限窗口={}ms | 判定依据=最新一代刷新令牌在宽限窗口内被并发重复使用",
                            clientId, familyId, presentedId, ageMillis, graceMillis);
                    return new RotationOutcome.ConcurrentRace(presentedId, family.getLastRotatedAt());
                }
                // 更早代际的已消费令牌再次出现，或最新代际超过宽限窗口：判定为重放，
                // 整条链路（含所有未过期访问令牌）立即失效。
                family.revoke(now, "REFRESH_REPLAY_DETECTED");
                int revokedCount = tokenStore.revokeAccessTokensByFamily(familyId,
                        "REFRESH_REPLAY_DETECTED").size();
                log.error("刷新拒绝（重放检测，链路整体撤销） | clientId={} | sessionId={} | 重放refreshTokenId={} | "
                                + "距上次轮换={}ms | 宽限窗口={}ms | 最新代际={} | 撤销访问令牌数={} | "
                                + "判定依据=更早代际的已消费刷新令牌被再次使用，或最新代际重放超过宽限窗口",
                        clientId, familyId, presentedId, ageMillis, graceMillis,
                        isLatestConsumedGeneration, revokedCount);
                return new RotationOutcome.ReplayDetected(presentedId);
            }
            return RotationOutcome.Rejection.UNKNOWN;
        });

        if (outcome == null) {
            outcome = RotationOutcome.Rejection.UNKNOWN;
        }
        return switch (outcome) {
            case RotationOutcome.Rotated rotated -> rotated.tokenPair();
            case RotationOutcome.ConcurrentRace ignored ->
                    throw new AuthException(AuthErrorCode.REFRESH_CONCURRENT_RACE);
            case RotationOutcome.ReplayDetected ignored ->
                    throw new AuthException(AuthErrorCode.REFRESH_REPLAY_DETECTED);
            case RotationOutcome.Rejection rejection -> {
                AuthErrorCode code = switch (rejection) {
                    case FAMILY_REVOKED -> AuthErrorCode.REFRESH_FAMILY_REVOKED;
                    case REFRESH_EXPIRED -> AuthErrorCode.REFRESH_TOKEN_EXPIRED;
                    case UNKNOWN -> AuthErrorCode.REFRESH_TOKEN_UNKNOWN;
                };
                throw new AuthException(code);
            }
        };
    }

    @Override
    public void logout(String clientId, String accessToken) {
        TokenParts parts = parseToken(accessToken, ACCESS_PREFIX);
        AccessTokenEntry entry = tokenStore.findAccess(parts.tokenId());
        if (entry == null || !entry.getFamilyId().equals(parts.familyId())
                || !entry.getClientId().equals(clientId)) {
            log.warn("注销拒绝 | clientId={} | 判定依据=访问令牌不存在或无法识别", clientId);
            throw new AuthException(AuthErrorCode.ACCESS_TOKEN_UNKNOWN);
        }
        TokenFamily family = tokenStore.findFamily(entry.getFamilyId());
        Instant now = Instant.now(clock);
        tokenStore.withFamilyLock(entry.getFamilyId(), f -> {
            f.revoke(now, "SESSION_REVOKED");
            return null;
        });
        int revokedCount = tokenStore.revokeAccessTokensByFamily(entry.getFamilyId(), "SESSION_REVOKED").size();
        log.info("会话注销 | clientId={} | username={} | sessionId={} | 撤销访问令牌数={} | "
                        + "判定依据=会话级撤销立即传播到所有未过期访问令牌",
                clientId, entry.getUsername(), entry.getFamilyId(), revokedCount);
    }

    @Override
    public AuthenticatedCaller authenticate(String accessToken) {
        TokenParts parts = parseToken(accessToken, ACCESS_PREFIX);
        AccessTokenEntry entry = tokenStore.findAccess(parts.tokenId());
        if (entry == null || !entry.getFamilyId().equals(parts.familyId())) {
            log.warn("访问拒绝 | clientId=未认证 | accessTokenId={} | 状态=未知 | 判定依据=访问令牌不存在或无法识别",
                    parts.tokenId());
            throw new AuthException(AuthErrorCode.ACCESS_TOKEN_UNKNOWN);
        }
        String clientId = entry.getClientId();
        if (entry.isRevoked()) {
            log.warn("访问拒绝 | clientId={} | sessionId={} | accessTokenId={} | 状态=已撤销 | "
                            + "判定依据=访问令牌已被会话注销/重放撤销",
                    clientId, entry.getFamilyId(), entry.getTokenId());
            throw new AuthException(AuthErrorCode.SESSION_REVOKED);
        }
        TokenFamily family = tokenStore.findFamily(entry.getFamilyId());
        if (family == null || family.isRevoked()) {
            log.warn("访问拒绝 | clientId={} | sessionId={} | accessTokenId={} | 状态=链路已撤销 | "
                            + "判定依据=刷新链路撤销立即传播到未过期访问令牌",
                    clientId, entry.getFamilyId(), entry.getTokenId());
            throw new AuthException(AuthErrorCode.SESSION_REVOKED);
        }
        Instant now = Instant.now(clock);
        if (!entry.getExpiresAt().isAfter(now)) {
            log.warn("访问拒绝 | clientId={} | sessionId={} | accessTokenId={} | 状态=已过期 | expiresAt={} | "
                            + "判定依据=访问令牌已过有效期",
                    clientId, entry.getFamilyId(), entry.getTokenId(), entry.getExpiresAt());
            throw new AuthException(AuthErrorCode.ACCESS_TOKEN_EXPIRED);
        }
        log.info("访问放行 | clientId={} | username={} | sessionId={} | accessTokenId={} | 状态=有效 | "
                        + "判定依据=访问令牌有效且会话未撤销",
                clientId, entry.getUsername(), entry.getFamilyId(), entry.getTokenId());
        return new AuthenticatedCaller(clientId, entry.getUsername(), entry.getFamilyId());
    }

    private static String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private static TokenParts parseToken(String token, String expectedPrefix) {
        if (token == null || token.isBlank()) {
            throw new AuthException(expectedPrefix.equals(ACCESS_PREFIX)
                    ? AuthErrorCode.ACCESS_TOKEN_MISSING
                    : AuthErrorCode.REFRESH_TOKEN_MISSING);
        }
        if (!token.startsWith(expectedPrefix)) {
            throw new AuthException(expectedPrefix.equals(ACCESS_PREFIX)
                    ? AuthErrorCode.ACCESS_TOKEN_UNKNOWN
                    : AuthErrorCode.REFRESH_TOKEN_UNKNOWN);
        }
        String body = token.substring(expectedPrefix.length());
        int dot = body.indexOf('.');
        if (dot <= 0 || dot == body.length() - 1
                || body.indexOf('.', dot + 1) >= 0) {
            throw new AuthException(expectedPrefix.equals(ACCESS_PREFIX)
                    ? AuthErrorCode.ACCESS_TOKEN_UNKNOWN
                    : AuthErrorCode.REFRESH_TOKEN_UNKNOWN);
        }
        return new TokenParts(body.substring(0, dot), body.substring(dot + 1));
    }

    private record TokenParts(String familyId, String tokenId) {
    }
}
