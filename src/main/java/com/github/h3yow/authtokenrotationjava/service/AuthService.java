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
     *
     * <p>All attempts for one family are serialized by the family's exclusive
     * lock. When the presented token has already been consumed, the verdict no
     * longer depends on <em>when</em> the losing thread happened to be
     * scheduled. It is derived from durable state instead:
     * <ol>
     *   <li>The consumed token remembers its successor (the refresh token
     *       issued by the winning rotation).</li>
     *   <li>If the reuse lands within the configured grace window of the
     *       rotation and the successor is still {@code ACTIVE}, it is a
     *       <b>benign concurrent conflict</b>: {@code refresh_conflict_concurrent}.
     *       The session is left untouched, so the winner's new pair keeps
     *       working and can rotate again. Every request in a concurrently
     *       fired batch gets this same verdict regardless of thread
     *       scheduling, and the conclusion is stable across re-runs.</li>
     *   <li>If the reuse arrives after the grace window has fully elapsed, or
     *       the successor itself has already been consumed, the old token is a
     *       genuine <b>sequential replay</b> after the rotation round ended:
     *       the whole chain is revoked while other families stay untouched.</li>
     * </ol>
     */
    public TokenPair rotate(String presentedRefreshToken, String callerId) {
        RefreshTokenRecord presented = store.findRefreshToken(presentedRefreshToken);
        if (presented == null) {
            logReject("refresh", AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "refresh_token_not_found_server_side");
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, null, "UNKNOWN",
                    "refresh token not found");
        }
        String familyId = presented.getFamilyId();
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
                ConflictClassification classification = classifyReuse(live, insideAt);
                if (classification.benign()) {
                    logReject("refresh", AuthErrorCode.REFRESH_CONFLICT_CONCURRENT, callerId, fid,
                            live.getState().name(), classification.basis());
                    throw new AuthException(AuthErrorCode.REFRESH_CONFLICT_CONCURRENT, callerId, fid,
                            live.getState().name(),
                            "concurrent refresh conflict: another in-batch attempt already rotated "
                                    + "this token; the winning new credentials remain valid");
                }
                revokeChain(current, Session.Status.COMPROMISED, insideAt,
                        "sequential_refresh_token_replay");
                logReject("refresh", AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, callerId, fid,
                        live.getState().name(), classification.basis());
                throw new AuthException(AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, callerId, fid,
                        live.getState().name(), "replay of an already rotated refresh token detected");
            }

            if (live.getExpiresAtMillis() <= insideAt) {
                logReject("refresh", AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, fid,
                        live.getState().name(),
                        "expiresAt=" + live.getExpiresAtMillis() + " now=" + insideAt);
                throw new AuthException(AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, fid,
                        live.getState().name(), "refresh token expired");
            }

            // Exactly one attempt reaches this point per refresh token. Build
            // the successor pair first, then perform the one-shot flip: under
            // the family lock both effects are visible atomically.
            TokenPair pair = issuePair(current, insideAt);
            if (!live.markRotated(insideAt, pair.refreshToken())) {
                // Defensive: another waiter consumed it between the check and
                // the flip. Apply the same durable classification.
                ConflictClassification classification = classifyReuse(live, insideAt);
                if (!classification.benign()) {
                    revokeChain(current, Session.Status.COMPROMISED, insideAt,
                            "sequential_refresh_token_replay");
                }
                AuthErrorCode code = classification.benign()
                        ? AuthErrorCode.REFRESH_CONFLICT_CONCURRENT
                        : AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL;
                logReject("refresh", code, callerId, fid, live.getState().name(),
                        "lost_atomic_state_flip " + classification.basis());
                throw new AuthException(code, callerId, fid, live.getState().name(),
                        "lost the atomic rotation race");
            }
            log.info("decision=refresh accepted=true callerId={} familyId={} refreshState=ROTATED "
                            + "accessState=ISSUED basis=active_token_atomic_rotation",
                    callerId, fid);
            return pair;
        });
    }

    /**
     * Decide whether reusing an already-consumed token is a benign concurrent
     * conflict or a genuine sequential replay. Purely a function of durable
     * state and the logical clock, hence independent of thread scheduling.
     */
    private ConflictClassification classifyReuse(RefreshTokenRecord consumed, long at) {
        long grace = properties.getRefreshConcurrentGraceMillis();
        boolean withinGrace = at - consumed.getRotatedAtMillis() <= grace;
        RefreshTokenRecord successor = consumed.getSuccessorRefreshToken() == null
                ? null : store.findRefreshToken(consumed.getSuccessorRefreshToken());
        boolean successorFresh = successor != null
                && successor.getState() == RefreshTokenRecord.State.ACTIVE
                && successor.getExpiresAtMillis() > at;
        String basis = "token_already_" + consumed.getState()
                + " rotatedAt=" + consumed.getRotatedAtMillis() + " now=" + at + " graceMs=" + grace
                + " withinGrace=" + withinGrace
                + " successorState=" + (successor == null ? "GONE" : successor.getState());
        boolean benign = withinGrace && successorFresh;
        return new ConflictClassification(benign, basis);
    }

    private record ConflictClassification(boolean benign, String basis) {
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
