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
     * Rotate a refresh token with a <b>scheduling-independent benign-concurrency
     * verdict</b>. Every attempt performs one atomic <em>first touch</em> on the
     * presented token <b>before any blocking</b>:
     * <ol>
     *   <li>The unique attempt that observes {@code ACTIVE} wins, claims the
     *       token as {@code ROTATING} and performs exactly one rotation inside
     *       the family's exclusive lock.</li>
     *   <li>Attempts that observe {@code ROTATING}, or {@code ROTATED} within the
     *       configurable overlap window, are members of the same concurrent
     *       batch. They all receive the same distinguishable benign verdict
     *       {@link AuthErrorCode#REFRESH_CONCURRENT_CONFLICT} (HTTP 409). The
     *       chain is <b>not</b> harmed and the winner's freshly issued pair
     *       stays usable for access and further rotation.</li>
     *   <li>A reuse of the consumed token <b>after</b> the overlap window has
     *       elapsed is a true post-hoc replay: the whole chain is terminated as
     *       {@code COMPROMISED}, exactly as in the previous revision.</li>
     * </ul>
     *
     * <p>The first touch depends only on the token's own state and wall-clock
     * distance from the finished rotation, never on thread ordering, so no
     * matter how a batch is scheduled or re-run there is always exactly one
     * success and every loser lands on the same conclusion.
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

        // THE single classification point. Atomic, pre-blocking, and the only
        // place the benign/malicious distinction is decided.
        RefreshTokenRecord.FirstTouch firstTouch =
                presented.firstTouch(now, properties.getRefreshConcurrentOverlapMillis());

        return switch (firstTouch) {
            case WINNER -> rotateAsWinner(presentedRefreshToken, presented, familyId, callerId);
            case CONCURRENT -> handleConcurrentContender(presentedRefreshToken, presented, familyId, callerId);
            case SEQUENTIAL_REPLAY -> handleSequentialReplay(presented, familyId, callerId);
            case CHAIN_TERMINATED -> handleChainTerminated(presented, familyId, callerId);
        };
    }

    private TokenPair rotateAsWinner(String presentedRefreshToken, RefreshTokenRecord presented,
                                     String familyId, String callerId) {
        try {
            return store.withFamilyLock(familyId, fid -> {
                long at = clock.nowMillis();
                Session current = store.findSession(fid);

                if (current != null && !callerId.equals(current.getCallerId())) {
                    // Not a rotation at all: hand the still-valid token back so
                    // its real owner is never harmed by a foreign attempt.
                    presented.rollbackToActive();
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, fid,
                            presented.getState().name(), "presented_caller_differs_from_chain_owner");
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, fid,
                            presented.getState().name(), "caller does not own this refresh chain");
                }
                if (current != null && current.getStatus() == Session.Status.LOGGED_OUT) {
                    presented.markRevoked();
                    logReject("refresh", AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, fid,
                            current.getStatus().name(), "session_status=LOGGED_OUT");
                    throw new AuthException(AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, fid,
                            current.getStatus().name(), "session has been logged out");
                }
                if (current != null && current.getStatus() == Session.Status.COMPROMISED) {
                    presented.markRevoked();
                    logReject("refresh", AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                            current.getStatus().name(), "session_status=COMPROMISED_due_to_replay");
                    throw new AuthException(AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                            current.getStatus().name(), "refresh chain invalidated by replay detection");
                }

                RefreshTokenRecord live = store.findRefreshToken(presentedRefreshToken);
                if (live == null) {
                    // Reclaimed mid-flight: release waiters with a plain unknown verdict.
                    presented.rollbackToActive();
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, fid, "UNKNOWN",
                            "refresh_token_disappeared_inside_lock");
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, callerId, fid, "UNKNOWN",
                            "refresh token not found");
                }
                if (live.getExpiresAtMillis() <= at) {
                    // Expiry is a property of time, not of the claim: the token
                    // is unusable for everyone, so no rollback, just revocation.
                    live.markRevoked();
                    logReject("refresh", AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, fid,
                            live.getState().name(),
                            "expiresAt=" + live.getExpiresAtMillis() + " now=" + at);
                    throw new AuthException(AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, fid,
                            live.getState().name(), "refresh token expired");
                }

                // Exactly one attempt reaches this point per refresh token:
                // state publication and issuance of the new pair are atomic.
                TokenPair pair = issuePair(current, at);
                live.completeRotation(at);
                log.info("decision=refresh accepted=true callerId={} familyId={} refreshState=ROTATED "
                                + "accessState=ISSUED basis=winner_first_touch_atomic_rotation",
                        callerId, fid);
                return pair;
            });
        } catch (RuntimeException ex) {
            // Defensive: if the in-lock action aborts without publishing a
            // terminal state, never leave waiters stuck on ROTATING.
            if (presented.getState() == RefreshTokenRecord.State.ROTATING) {
                presented.rollbackToActive();
            }
            throw ex;
        }
    }

    private TokenPair handleConcurrentContender(String presentedRefreshToken, RefreshTokenRecord presented,
                                                String familyId, String callerId) {
        // A foreign caller riding a concurrent batch still cannot see or move
        // the chain; that verdict is more specific than the conflict verdict.
        Session session = store.findSession(familyId);
        if (session != null && !callerId.equals(session.getCallerId())) {
            logReject("refresh", AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, familyId,
                    presented.getState().name(), "concurrent_presenter_differs_from_chain_owner");
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_CALLER_MISMATCH, callerId, familyId,
                    presented.getState().name(), "caller does not own this refresh chain");
        }
        long waitBound = Math.max(properties.getRefreshConcurrentOverlapMillis(), 1L);
        boolean resolved;
        try {
            resolved = presented.awaitResolution(waitBound);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AuthException(AuthErrorCode.REFRESH_INFLIGHT_TIMEOUT, callerId, familyId,
                    presented.getState().name(), "interrupted while waiting for the in-flight rotation");
        }
        if (!resolved) {
            logReject("refresh", AuthErrorCode.REFRESH_INFLIGHT_TIMEOUT, callerId, familyId,
                    presented.getState().name(), "winner_still_inflight_after_overlap_bound");
            throw new AuthException(AuthErrorCode.REFRESH_INFLIGHT_TIMEOUT, callerId, familyId,
                    presented.getState().name(), "the in-flight rotation did not finish in time");
        }

        // The winner has published. Re-read terminal session state first.
        Session after = store.findSession(familyId);
        if (after != null && after.getStatus() == Session.Status.COMPROMISED) {
            logReject("refresh", AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, familyId,
                    after.getStatus().name(), "session_status=COMPROMISED_while_waiting");
            throw new AuthException(AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, familyId,
                    after.getStatus().name(), "refresh chain invalidated by replay detection");
        }
        if (after != null && after.getStatus() == Session.Status.LOGGED_OUT) {
            logReject("refresh", AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, familyId,
                    after.getStatus().name(), "session_status=LOGGED_OUT_while_waiting");
            throw new AuthException(AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, familyId,
                    after.getStatus().name(), "session has been logged out");
        }
        // Winner rolled back because it failed on a non-terminal condition
        // (e.g. expiry, disappearance): reclassify by the current token state.
        RefreshTokenRecord latest = store.findRefreshToken(presentedRefreshToken);
        if (latest != null && latest.getState() == RefreshTokenRecord.State.ACTIVE) {
            return rotate(presentedRefreshToken, callerId);
        }
        if (latest != null && latest.getState() == RefreshTokenRecord.State.REVOKED) {
            long now = clock.nowMillis();
            if (latest.getExpiresAtMillis() <= now) {
                logReject("refresh", AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, familyId,
                        latest.getState().name(), "winner_failed_due_to_expiry");
                throw new AuthException(AuthErrorCode.REFRESH_TOKEN_EXPIRED, callerId, familyId,
                        latest.getState().name(), "refresh token expired");
            }
        }

        // Benign concurrent conflict: same token presented by an overlapping
        // attempt (or by a thread scheduled late but still inside the overlap
        // window). No chain harm; the winner's pair remains fully usable.
        String state = latest == null ? "UNKNOWN" : latest.getState().name();
        logReject("refresh", AuthErrorCode.REFRESH_CONCURRENT_CONFLICT, callerId, familyId, state,
                "duplicate_presentation_overlaps_finished_or_inflight_rotation_within_window_ms="
                        + properties.getRefreshConcurrentOverlapMillis());
        throw new AuthException(AuthErrorCode.REFRESH_CONCURRENT_CONFLICT, callerId, familyId, state,
                "concurrent use of the same refresh token; exactly one attempt wins and the chain is preserved");
    }

    private TokenPair handleSequentialReplay(RefreshTokenRecord presented, String familyId, String callerId) {
        long now = clock.nowMillis();
        return store.withFamilyLock(familyId, fid -> {
            Session current = store.findSession(fid);
            if (current != null && current.getStatus() == Session.Status.COMPROMISED) {
                logReject("refresh", AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                        current.getStatus().name(), "session_status=COMPROMISED_due_to_replay");
                throw new AuthException(AuthErrorCode.CHAIN_REVOKED_REPLAY, callerId, fid,
                        current.getStatus().name(), "refresh chain invalidated by replay detection");
            }
            if (current != null && current.getStatus() == Session.Status.LOGGED_OUT) {
                logReject("refresh", AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, fid,
                        current.getStatus().name(), "session_status=LOGGED_OUT");
                throw new AuthException(AuthErrorCode.CHAIN_REVOKED_LOGOUT, callerId, fid,
                        current.getStatus().name(), "session has been logged out");
            }
            // The consumed token was re-presented strictly after the benign
            // overlap window: a genuine post-hoc replay. The whole chain dies,
            // including the pair that the legitimate rotation had issued.
            revokeChain(current, Session.Status.COMPROMISED, now, "sequential_refresh_token_replay");
            presented.markRevoked();
            logReject("refresh", AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, callerId, fid,
                    presented.getState().name(),
                    "token_already_" + presented.getState() + "_and_overlap_window_"
                            + properties.getRefreshConcurrentOverlapMillis() + "ms_elapsed");
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_REPLAY_SEQUENTIAL, callerId, fid,
                    presented.getState().name(),
                    "replay of an already rotated refresh token after the concurrent overlap window");
        });
    }

    private TokenPair handleChainTerminated(RefreshTokenRecord presented, String familyId, String callerId) {
        Session current = store.findSession(familyId);
        Session.Status status = current == null ? null : current.getStatus();
        AuthErrorCode code = status == Session.Status.LOGGED_OUT
                ? AuthErrorCode.CHAIN_REVOKED_LOGOUT
                : AuthErrorCode.CHAIN_REVOKED_REPLAY;
        logReject("refresh", code, callerId, familyId, presented.getState().name(),
                "refresh_token_already_" + presented.getState());
        throw new AuthException(code, callerId, familyId, presented.getState().name(),
                "refresh chain already terminated");
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
        // Token and session are read in one family-locked snapshot, so a
        // concurrent rotation, logout or reclamation run can never make the two
        // observations disagree. Session status is consulted on every call:
        // revoking the family makes every unexpired access token fail
        // immediately, no denylist delay.
        TokenStore.AccessSnapshot snapshot = store.snapshotAccessToken(opaqueAccessToken);
        AccessTokenRecord record = snapshot.access();
        Session session = snapshot.session();
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
