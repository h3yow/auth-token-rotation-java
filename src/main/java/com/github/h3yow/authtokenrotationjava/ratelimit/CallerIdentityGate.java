package com.github.h3yow.authtokenrotationjava.ratelimit;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Server-side trust boundary in front of the rate-limit accounting. The
 * declared {@code X-Caller-Id} header is never trusted as a quota key: the
 * presented credential is resolved against server-side state first, and the
 * request is charged only to the <em>attested</em> owner.
 *
 * <ul>
 *   <li>Entry points without a credential (login, ops) are charged to the
 *       shared {@link CallerRateLimiter.Tier#UNAUTHENTICATED} bucket.</li>
 *   <li>Requests carrying a valid credential are charged
 *       {@link CallerRateLimiter.Tier#TRUSTED} to the credential's owner, even
 *       if the header lies about who presents it &mdash; so spoofing a header
 *       cannot spend anyone else's quota.</li>
 *   <li>Requests with a missing, forged or invalid credential are charged to
 *       the shared {@link CallerRateLimiter.Tier#UNTRUSTED} bucket and rejected
 *       with a distinct, pre-existing security code; no real caller quota moves.</li>
 * </ul>
 */
@Component
public class CallerIdentityGate {

    private static final Logger log = LoggerFactory.getLogger(CallerIdentityGate.class);

    private final CallerRateLimiter rateLimiter;
    private final TokenStore store;

    public CallerIdentityGate(CallerRateLimiter rateLimiter, TokenStore store) {
        this.rateLimiter = rateLimiter;
        this.store = store;
    }

    /**
     * Charge a pre-credential entry point (login / ops). A missing caller
     * declaration is rejected outright with its own 400 code and is not charged
     * anywhere; otherwise the shared unauthenticated bucket is charged.
     */
    public RateLimitDecision chargeUnauthenticated(String declaredCallerId, String endpoint) {
        if (declaredCallerId == null || declaredCallerId.isBlank()) {
            log.warn("decision=rate_limit accepted=false tier=UNAUTHENTICATED endpoint={} tokenState=- "
                            + "reason=caller_identity_missing basis=header_X_Caller_Id_absent "
                            + "real_caller_quota_charged=false",
                    endpoint);
            throw new AuthException(AuthErrorCode.CALLER_IDENTITY_MISSING, null, null, "-",
                    "missing caller identity header X-Caller-Id");
        }
        RateLimitDecision decision = rateLimiter.checkAndRegister(
                CallerRateLimiter.Tier.UNAUTHENTICATED, null);
        logProbe("unauthenticated:" + endpoint, declaredCallerId, decision);
        if (!decision.allowed()) {
            throw new AuthException(AuthErrorCode.RATE_LIMIT_EXCEEDED, null, null, "-",
                    "unauthenticated entry point rate limit exceeded");
        }
        return decision;
    }

    /**
     * Resolve the server-attested owner of a refresh credential and charge that
     * owner's trusted bucket. An unknown/garbage token is charged only to the
     * untrusted bucket and rejected with {@code refresh_token_unknown}.
     */
    public void chargeRefresh(String refreshToken, String declaredCallerId) {
        if (declaredCallerId == null || declaredCallerId.isBlank()) {
            chargeUntrustedAndReject(declaredCallerId, "missing",
                    AuthErrorCode.CALLER_IDENTITY_MISSING,
                    "missing caller identity header X-Caller-Id");
        }
        var record = refreshToken == null ? null : store.findRefreshToken(refreshToken);
        if (record == null) {
            chargeUntrustedAndReject(declaredCallerId, "UNKNOWN",
                    AuthErrorCode.REFRESH_TOKEN_UNKNOWN, "refresh token not found");
        }
        // Owner identity comes from the server-side record, never the header.
        chargeTrustedOwner(record.getFamilyId(), declaredCallerId,
                lookupRefreshOwner(record.getFamilyId()), "refresh");
    }

    /**
     * Resolve the server-attested owner of a Bearer access token and charge that
     * owner's trusted bucket. A missing/unknown bearer is charged only to the
     * untrusted bucket and rejected with its distinct security code; the actual
     * access decision (expiry, revocation, header-vs-owner mismatch) is left to
     * {@code AuthService} after gating.
     */
    public void chargeAccess(String bearerToken, String declaredCallerId) {
        if (declaredCallerId == null || declaredCallerId.isBlank()) {
            chargeUntrustedAndReject(declaredCallerId, "missing",
                    AuthErrorCode.CALLER_IDENTITY_MISSING,
                    "missing caller identity header X-Caller-Id");
        }
        if (bearerToken == null || bearerToken.isBlank()) {
            chargeUntrustedAndReject(declaredCallerId, "MISSING",
                    AuthErrorCode.ACCESS_TOKEN_MISSING, "no bearer token presented");
        }
        TokenStore.AccessSnapshot snapshot = store.snapshotAccessToken(bearerToken);
        AccessTokenRecord record = snapshot.access();
        if (record == null) {
            chargeUntrustedAndReject(declaredCallerId, "UNKNOWN",
                    AuthErrorCode.ACCESS_TOKEN_UNKNOWN, "access token not found");
        }
        chargeTrustedOwner(record.getFamilyId(), declaredCallerId, record.getCallerId(), "access");
    }

    private String lookupRefreshOwner(String familyId) {
        var session = store.findSession(familyId);
        return session == null ? null : session.getCallerId();
    }

    private void chargeTrustedOwner(String familyId, String declaredCallerId, String attestedOwner,
                                    String action) {
        if (attestedOwner == null) {
            // Credential exists but its family/session is gone: cannot attribute
            // it to any real caller, so it must not touch a real caller quota.
            chargeUntrustedAndReject(declaredCallerId, "ORPHAN",
                    AuthErrorCode.REFRESH_TOKEN_UNKNOWN, "credential has no attributable owner");
        }
        RateLimitDecision decision = rateLimiter.checkAndRegister(
                CallerRateLimiter.Tier.TRUSTED, attestedOwner);
        logProbe("trusted:" + action, declaredCallerId + " attestedOwner=" + attestedOwner
                + " familyId=" + familyId, decision);
        if (!decision.allowed()) {
            throw new AuthException(AuthErrorCode.RATE_LIMIT_EXCEEDED, attestedOwner, familyId, "-",
                    "rate limit exceeded for attested caller " + attestedOwner);
        }
    }

    private void chargeUntrustedAndReject(String declaredCallerId, String tokenState,
                                          AuthErrorCode code, String detail) {
        RateLimitDecision decision = rateLimiter.checkAndRegister(
                CallerRateLimiter.Tier.UNTRUSTED, null);
        log.warn("decision=rate_limit accepted=false tier=UNTRUSTED declaredCallerId={} tokenState={} "
                        + "reason={} basis=identity_or_credential_not_server_attested count={} limit={} "
                        + "real_caller_quota_charged=false",
                declaredCallerId, tokenState, code.code(),
                decision.requestCountInWindow(), decision.limit());
        // The untrusted flood bucket itself is saturated: the distinguishable
        // conclusion is still the rate-limit code rather than a real quota.
        if (!decision.allowed()) {
            throw new AuthException(AuthErrorCode.RATE_LIMIT_EXCEEDED, null, null, tokenState,
                    "untrusted request bucket rate limit exceeded");
        }
        throw new AuthException(code, declaredCallerId, null, tokenState, detail);
    }

    private void logProbe(String tier, String identityDesc, RateLimitDecision decision) {
        if (decision.allowed()) {
            log.debug("decision=rate_limit accepted=true tier={} identity={} count={} limit={}",
                    tier, identityDesc, decision.requestCountInWindow(), decision.limit());
        } else {
            log.warn("decision=rate_limit accepted=false tier={} identity={} reason=rate_limit_exceeded "
                            + "basis=sliding_window count={} limit={}",
                    tier, identityDesc, decision.requestCountInWindow(), decision.limit());
        }
    }
}
