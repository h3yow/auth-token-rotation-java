package com.github.h3yow.authtokenrotationjava.service;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import com.github.h3yow.authtokenrotationjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Core authentication service: login, atomic rotating refresh, logout and
 * access-token verification. Every decision is logged with caller identity,
 * token state and the decision basis.
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final TokenStore store;
    private final TokenFactory tokenFactory;
    private final SecurityProperties properties;
    private final Clock clock;

    public AuthService(TokenStore store, TokenFactory tokenFactory,
                       SecurityProperties properties, Clock clock) {
        this.store = store;
        this.tokenFactory = tokenFactory;
        this.properties = properties;
        this.clock = clock;
    }

    /** Issue a brand-new session and its first token pair. */
    public TokenPair login(String subject, String callerId) {
        long now = clock.nowMillis();
        String familyId = UUID.randomUUID().toString();
        Session session = new Session(familyId, subject, callerId, now);
        store.saveSession(session);
        TokenPair pair = issuePair(session, now);
        log.info("decision=login accepted=true callerId={} subject={} familyId={} "
                + "accessState=ISSUED refreshState=ISSUED basis=credentials_accepted",
                callerId, subject, familyId);
        return pair;
    }

    /**
     * Atomically invalidate the presented refresh token and return a new pair.
     * Concurrent or repeated use of the same refresh token fails with a
     * distinguishable code and revokes the whole chain.
     *
     * <p>Synchronization model:
     * <ol>
     *   <li>A per-family single-holder gate rejects every attempt that overlaps
     *       another in-flight rotation for the same family. The winner enters
     *       the family's exclusive lock; losers block on that lock.</li>
     *   <li>Inside the lock, the winner rotates exactly once. When losers enter
     *       after the winner, the token state and the still-open gate together
     *       prove the overlap, so they are classified as a <em>concurrent</em>
     *       replay. A later replay after the gate has closed is a
     *       <em>sequential</em> replay.</li>
     *   <li>Either replay verdict revokes the entire chain (session, all access
     *       tokens via the family status, and all future refresh attempts),
     *       while other families remain untouched.</li>
     * </ol>
     */
    public TokenPair rotate(String presentedRefreshToken, String callerId) {
        long now = clock.nowMillis();
        RefreshTokenRecord presented = store.findRefreshToken(presentedRefreshToken);
        if (presented == null) {
            logReject("refresh", AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "refresh_token_not_found_server_side");
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "refresh token not found");
        }
        String familyId = presented.getFamilyId();
        Session session = store.findSession(familyId);
        String attemptId = UUID.randomUUID().toString();
        boolean gateAcquired = store.tryAcquireFamilyGate(familyId, attemptId);
        try {
            return store.withFamilyLock(familyId, fid -> {
                long insideAt = clock.nowMillis();
                Session current = store.findSession(fid);

                if (current != null && !callerId.equals(current.getCallerId())) {
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, fid,
                            presented.getState().name(), "presented_caller_differs_from_chain_owner");
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, fid,
                            presented.getState().name(), "caller does not own this refresh chain");
                }

                if (current != null && current.getStatus() == Session.Status.LOGGED_OUT) {
                    logReject("refresh", AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, fid,
                            current.getStatus().name(), "session_status=LOGGED_OUT");
                    throw new AuthException(AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, fid,
                            current.getStatus().name(), "session has been logged out");
                }
                if (current != null && current.getStatus() == Session.Status.COMPROMISED) {
                    logReject("refresh", AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                            current.getStatus().name(), "session_status=COMPROMISED_due_to_replay");
                    throw new AuthException(AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                            current.getStatus().name(), "refresh chain invalidated by replay detection");
                }

                RefreshTokenRecord live = store.findRefreshToken(presentedRefreshToken);
                if (live == null) {
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, fid, "UNKNOWN",
                            "refresh_token_disappeared_inside_lock");
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, fid, "UNKNOWN",
                            "refresh token not found");
                }

                if (live.getState() != RefreshTokenRecord.State.ACTIVE) {
                    // The token was already consumed. A still-open gate means the
                    // consumption happened on an overlapping attempt (concurrent
                    // replay); a closed gate means an attacker replayed it later.
                    boolean concurrent = !gateAcquired;
                    revokeChain(current, Session.Status.COMPROMISED, insideAt,
                            concurrent ? "concurrent_refresh_token_replay" : "sequential_refresh_token_replay");
                    AuthErrorCode code = concurrent
                            ? AuthErrorCode.REFRESH_TOKEN_REPLAY_CONCURRENT
                            : AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL;
                    logReject("refresh", code, callerId, fid, live.getState().name(),
                            concurrent ? "gate_still_open_and_token_already_" + live.getState()
                                       : "gate_closed_token_already_" + live.getState());
                    throw new AuthException(code, callerId, fid, live.getState().name(),
                            concurrent ? "concurrent reuse of a refresh token detected"
                                       : "replay of an already rotated refresh token detected");
                }

                if (live.getExpiresAtMillis() <= insideAt) {
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, fid,
                            live.getState().name(),
                            "expiresAt=" + live.getExpiresAtMillis() + " now=" + insideAt);
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, fid,
                            live.getState().name(), "refresh token expired");
                }

                // Exactly one attempt reaches this point per refresh token:
                // the state flip and the issuance of the new pair are atomic.
                if (!live.markRotated(insideAt)) {
                    revokeChain(current, Session.Status.COMPROMISED, insideAt, "concurrent_refresh_token_replay");
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_REPLAY_CONCURRENT, callerId, fid,
                            live.getState().name(), "lost_atomic_state_flip");
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_REPLAY_CONCURRENT, callerId, fid,
                            live.getState().name(), "concurrent refresh lost the atomic rotation race");
                }
                TokenPair pair = issuePair(current, insideAt);
                log.info("decision=refresh accepted=true callerId={} familyId={} refreshState=ROTATED "
                                + "accessState=ISSUED basis=active_token_atomic_rotation attemptId={}",
                        callerId, fid, attemptId);
                return pair;
            });
        } finally {
            // Winner releases after the lock is freed and losers have finished
            // observing the open gate, so concurrent replay is never misclassified.
            store.releaseFamilyGate(familyId, attemptId);
        }
    }

    /**
     * Session-level revocation. The chain (and therefore every still-valid
     * access token in it) becomes unusable immediately. Logging out a chain
     * that was killed by replay is still reported as the replay verdict, so the
     * security conclusion is never masked.
     */
    public void logout(String presentedRefreshToken, String callerId) {
        long now = clock.nowMillis();
        RefreshTokenRecord presented = store.findRefreshToken(presentedRefreshToken);
        if (presented == null) {
            logReject("logout", AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "refresh_token_not_found_server_side");
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "refresh token not found");
        }
        String familyId = presented.getFamilyId();
        store.withFamilyLock(familyId, fid -> {
            Session session = store.findSession(fid);
            if (session != null && !callerId.equals(session.getCallerId())) {
                logReject("logout", AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, fid,
                        presented.getState().name(), "presented_caller_differs_from_chain_owner");
                throw new AuthException(AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, fid,
                        presented.getState().name(), "caller does not own this refresh chain");
            }
            if (session != null && session.getStatus() == Session.Status.COMPROMISED) {
                logReject("logout", AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                        session.getStatus().name(), "session_status=COMPROMISED_due_to_replay");
                throw new AuthException(AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                        session.getStatus().name(), "refresh chain invalidated by replay detection");
            }
            if (session != null && session.getStatus() == Session.Status.LOGGED_OUT) {
                // Idempotent logout: repeated logout of an already logged-out
                // chain is a success with an explicit basis.
                log.info("decision=logout accepted=true callerId={} familyId={} refreshState={} "
                                + "accessState=REVOKED basis=already_logged_out_idempotent",
                        callerId, fid, presented.getState());
                return null;
            }
            revokeChain(session, Session.Status.LOGGED_OUT, now, "user_logout");
            log.info("decision=logout accepted=true callerId={} familyId={} refreshState=REVOKED "
                            + "accessState=REVOKED basis=user_logout_propagates_immediately",
                    callerId, fid);
            return null;
        });
    }

    /** Verify an opaque access token against its live server-side state. */
    public AccessVerification verifyAccessToken(String opaqueAccessToken, String callerId) {
        long now = clock.nowMillis();
        if (opaqueAccessToken == null || opaqueAccessToken.isBlank()) {
            AccessVerification v = AccessVerification.rejected(
                    AuthErrorCode.ACCESS_TOKEN_MISSING.code(), callerId, null, "MISSING");
            logReject("access", AuthErrorCode.ACCESS_TOKEN_MISSING, callerId, null, "MISSING",
                    "no_authorization_header_token");
            return v;
        }
        AccessTokenRecord record = store.findAccessToken(opaqueAccessToken);
        if (record == null) {
            AccessVerification v = AccessVerification.rejected(
                    AuthErrorCode.ACCESS_TOKEN_UNKNOWN.code(), callerId, opaqueAccessToken, "UNKNOWN");
            logReject("access", AuthErrorCode.ACCESS_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "access_token_not_found_server_side");
            return v;
        }
        if (!callerId.equals(record.getCallerId())) {
            AccessVerification v = new AccessVerification(false,
                    AuthErrorCode.ACCESS_TOKEN_CALLER_MISMATCH.code(), callerId, record.getSubject(),
                    record.getFamilyId(), record.getTokenId(), "ACTIVE");
            logReject("access", AuthErrorCode.ACCESS_TOKEN_CALLER_MISMATCH, callerId,
                    record.getFamilyId(), "ACTIVE", "presented_caller_differs_from_token_owner");
            return v;
        }
        // Session status is consulted on every call: revoking the family makes
        // every unexpired access token fail immediately, no denylist delay.
        Session session = store.findSession(record.getFamilyId());
        if (session != null && session.getStatus() == Session.Status.LOGGED_OUT) {
            AccessVerification v = new AccessVerification(false,
                    AuthErrorCode.ACCESS_TOKEN_REVOKED_LOGOUT.code(), callerId, record.getSubject(),
                    record.getFamilyId(), record.getTokenId(), "SESSION_LOGGED_OUT");
            logReject("access", AuthErrorCode.ACCESS_TOKEN_REVOKED_LOGOUT, callerId,
                    record.getFamilyId(), "SESSION_LOGGED_OUT", "session_status=LOGGED_OUT");
            return v;
        }
        if ((session != null && session.getStatus() == Session.Status.COMPROMISED) || record.isRevoked()) {
            AccessVerification v = new AccessVerification(false,
                    AuthErrorCode.ACCESS_TOKEN_REVOKED_REPLAY.code(), callerId, record.getSubject(),
                    record.getFamilyId(), record.getTokenId(), "SESSION_COMPROMISED");
            logReject("access", AuthErrorCode.ACCESS_TOKEN_REVOKED_REPLAY, callerId,
                    record.getFamilyId(), "SESSION_COMPROMISED", "session_status=COMPROMISED_due_to_replay");
            return v;
        }
        if (record.getExpiresAtMillis() <= now) {
            AccessVerification v = new AccessVerification(false,
                    AuthErrorCode.ACCESS_TOKEN_EXPIRED.code(), callerId, record.getSubject(),
                    record.getFamilyId(), record.getTokenId(), "EXPIRED");
            logReject("access", AuthErrorCode.ACCESS_TOKEN_EXPIRED, callerId, record.getFamilyId(),
                    "EXPIRED", "expiresAt=" + record.getExpiresAtMillis() + " now=" + now);
            return v;
        }
        AccessVerification accepted = new AccessVerification(true, "access_token_valid", callerId,
                record.getSubject(), record.getFamilyId(), record.getTokenId(), "ACTIVE");
        log.info("decision=access accepted=true callerId={} subject={} familyId={} tokenId={} "
                        + "tokenState=ACTIVE basis=session_active_token_unexpired",
                callerId, record.getSubject(), record.getFamilyId(), record.getTokenId());
        return accepted;
    }

    /**
     * Create and persist a fresh pair for a session. The refresh token shares
     * the session's family id, so a rotation chain stays one revocable unit.
     */
    private TokenPair issuePair(Session session, long now) {
        String accessToken = tokenFactory.newToken("atk");
        String refreshToken = tokenFactory.newToken("rtk");
        long accessExpiresAt = now + properties.getAccessTokenTtlMillis();
        long refreshExpiresAt = now + properties.getRefreshTokenTtlMillis();

        AccessTokenRecord accessRecord = new AccessTokenRecord(
                accessToken, session.getFamilyId(), session.getSubject(), session.getCallerId(),
                now, accessExpiresAt);
        RefreshTokenRecord refreshRecord = new RefreshTokenRecord(
                refreshToken, session.getFamilyId(), now, refreshExpiresAt);

        store.saveAccessToken(accessToken, accessRecord);
        store.saveRefreshToken(refreshToken, refreshRecord);
        return new TokenPair(accessToken, refreshToken, session.getFamilyId(),
                accessExpiresAt, refreshExpiresAt);
    }

    private void revokeChain(Session session, Session.Status terminal, long at, String reason) {
        if (session != null) {
            session.revoke(terminal, at, reason);
        }
    }

    private void logReject(String action, AuthErrorCode code, String callerId, String familyId,
                           String tokenState, String basis) {
        log.warn("decision={} accepted=false callerId={} familyId={} tokenState={} reason={} basis={}",
                action, callerId, familyId, tokenState, code.code(), basis);
    }
}
