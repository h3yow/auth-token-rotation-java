package com.github.h3yow.authtokenrotationjava.maintenance;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import com.github.h3yow.authtokenrotationjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Controlled, concurrency-safe reclamation of state that is <em>provably dead
 * forever</em>:
 * <ul>
 *   <li>sessions in a terminal status ({@code LOGGED_OUT} / {@code COMPROMISED});</li>
 *   <li>refresh tokens in a terminal status ({@code REVOKED});</li>
 *   <li>access tokens revoked explicitly or by a terminal owning session;</li>
 *   <li>refresh/access tokens whose lifetime has fully elapsed.</li>
 * </ul>
 *
 * <p>Safety properties:
 * <ul>
 *   <li>Every removal decision is re-checked inside that family's exclusive
 *       lock, exactly where rotation/logout/verification mutate state, so a
 *       sweep running concurrently with live traffic can never remove a record
 *       that became valid in between the scan and the delete.</li>
 *   <li>Expiry uses the same predicate as authentication
 *       ({@code expiresAt <= now}): a credential exactly at its boundary is
 *       treated as expired here too &mdash; a boundary credential is never
 *       retained as valid nor an unexpired one collected early.</li>
 *   <li>An active, unexpired session and its live credentials are never
 *       touched. Terminal sessions are removed last, only once they hold no
 *       outstanding refresh credential, so no orphan token is left pointing at
 *       a missing session.</li>
 * </ul>
 *
 * <p>The sweep is synchronous and on-demand; it can run while requests are in
 * flight (see {@code POST /api/auth/maintenance/reclaim}).
 */
@Component
public class StateReclaimer {

    /** Category of a single removal, captured from live in-lock state. */
    private enum Removed {
        NONE,
        TERMINAL,
        EXPIRED
    }

    private static final Logger log = LoggerFactory.getLogger(StateReclaimer.class);

    private final TokenStore store;
    private final Clock clock;

    public StateReclaimer(TokenStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** Run one safe reclamation sweep and report what was removed. */
    public ReclaimReport reclaim() {
        long now = clock.nowMillis();

        long refreshScanned = 0;
        long refreshTerminalRemoved = 0;
        long refreshExpiredRemoved = 0;
        for (Map.Entry<String, RefreshTokenRecord> entry : store.allRefreshTokens()) {
            refreshScanned++;
            String token = entry.getKey();
            String familyId = entry.getValue().getFamilyId();
            Removed removed = store.withFamilyLock(familyId, fid -> {
                RefreshTokenRecord live = store.findRefreshToken(token);
                if (live == null) {
                    return Removed.NONE;
                }
                Session owner = store.findSession(familyId);
                boolean terminal = live.getState() == RefreshTokenRecord.State.REVOKED
                        || (owner != null && owner.getStatus() != Session.Status.ACTIVE);
                if (terminal) {
                    store.removeRefreshToken(token);
                    return Removed.TERMINAL;
                }
                if (live.getExpiresAtMillis() <= now) {
                    store.removeRefreshToken(token);
                    return Removed.EXPIRED;
                }
                return Removed.NONE;
            });
            if (removed == Removed.TERMINAL) {
                refreshTerminalRemoved++;
            } else if (removed == Removed.EXPIRED) {
                refreshExpiredRemoved++;
            }
        }

        long accessScanned = 0;
        long accessTerminalRemoved = 0;
        long accessExpiredRemoved = 0;
        for (Map.Entry<String, AccessTokenRecord> entry : store.allAccessTokens()) {
            accessScanned++;
            String token = entry.getKey();
            String familyId = entry.getValue().getFamilyId();
            Removed removed = store.withFamilyLock(familyId, fid -> {
                TokenStore.AccessSnapshot snapshot = store.snapshotAccessToken(token);
                AccessTokenRecord live = snapshot.access();
                if (live == null) {
                    return Removed.NONE;
                }
                boolean terminal = live.isRevoked()
                        || (snapshot.session() != null
                        && snapshot.session().getStatus() != Session.Status.ACTIVE);
                if (terminal) {
                    store.removeAccessToken(token);
                    return Removed.TERMINAL;
                }
                if (live.getExpiresAtMillis() <= now) {
                    store.removeAccessToken(token);
                    return Removed.EXPIRED;
                }
                return Removed.NONE;
            });
            if (removed == Removed.TERMINAL) {
                accessTerminalRemoved++;
            } else if (removed == Removed.EXPIRED) {
                accessExpiredRemoved++;
            }
        }

        // Sessions last. A session is collectable when it can never serve any
        // future request: it is either terminal, or it holds no usable refresh
        // credential and no live (unexpired, non-terminal) access token. Token
        // collections above have already removed everything dead, so "holds no
        // token at all" is computed from the surviving maps inside the lock.
        Set<String> familiesWithRefresh = new HashSet<>();
        for (Map.Entry<String, RefreshTokenRecord> e : store.allRefreshTokens()) {
            familiesWithRefresh.add(e.getValue().getFamilyId());
        }
        Set<String> familiesWithAccess = new HashSet<>();
        for (Map.Entry<String, AccessTokenRecord> e : store.allAccessTokens()) {
            familiesWithAccess.add(e.getValue().getFamilyId());
        }
        long sessionsScanned = 0;
        long sessionsRemoved = 0;
        for (Map.Entry<String, Session> entry : store.allSessions()) {
            sessionsScanned++;
            String familyId = entry.getKey();
            boolean removed = Boolean.TRUE.equals(store.withFamilyLock(familyId, fid -> {
                Session live = store.findSession(fid);
                if (live == null) {
                    return false;
                }
                boolean terminal = live.getStatus() != Session.Status.ACTIVE;
                boolean noRefresh = !familiesWithRefresh.contains(familyId);
                boolean noAccess = !familiesWithAccess.contains(familyId);
                if (terminal || (noRefresh && noAccess)) {
                    store.removeSession(familyId);
                    return true;
                }
                return false;
            }));
            if (removed) {
                sessionsRemoved++;
            }
        }

        long totalRemoved = sessionsRemoved + refreshTerminalRemoved + refreshExpiredRemoved
                + accessTerminalRemoved + accessExpiredRemoved;
        ReclaimReport report = new ReclaimReport(now, sessionsScanned, sessionsRemoved,
                refreshScanned, refreshTerminalRemoved, refreshExpiredRemoved,
                accessScanned, accessTerminalRemoved, accessExpiredRemoved, totalRemoved);
        log.info("decision=reclaim accepted=true at={} sessions(scanned={},removed={}) "
                        + "refresh(scanned={},terminalRemoved={},expiredRemoved={}) "
                        + "access(scanned={},terminalRemoved={},expiredRemoved={}) totalRemoved={}",
                now, sessionsScanned, sessionsRemoved,
                refreshScanned, refreshTerminalRemoved, refreshExpiredRemoved,
                accessScanned, accessTerminalRemoved, accessExpiredRemoved, totalRemoved);
        return report;
    }
}
