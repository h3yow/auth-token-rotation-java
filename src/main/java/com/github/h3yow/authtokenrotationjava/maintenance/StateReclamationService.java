package com.github.h3yow.authtokenrotationjava.maintenance;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import com.github.h3yow.authtokenrotationjava.ratelimit.CallerRateLimiter;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import com.github.h3yow.authtokenrotationjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Controlled reclamation of state that can never influence another decision:
 * terminal (logged out / compromised) families, families whose every token
 * has naturally expired, orphaned token records, and idle rate-limit windows.
 *
 * <p>Every family is re-checked and removed while holding that family's own
 * lock, so the sweep is safe to trigger concurrently with live traffic: a
 * still-valid family is never removed, and a token expiring at the exact sweep
 * instant is treated as expired (boundary inclusive, matching the rest of the
 * system: {@code expiresAt <= now}).
 */
@Service
public class StateReclamationService {

    public static final String CAT_SESSION_TERMINAL = "session_terminal";
    public static final String CAT_SESSION_EXPIRED = "session_all_tokens_expired";
    public static final String CAT_REFRESH_TOKENS = "refresh_token_records";
    public static final String CAT_ACCESS_TOKENS = "access_token_records";
    public static final String CAT_ORPHAN_REFRESH = "orphan_refresh_token_records";
    public static final String CAT_ORPHAN_ACCESS = "orphan_access_token_records";
    public static final String CAT_IDLE_RATE_LIMIT_KEYS = "idle_rate_limit_keys";

    private static final Logger log = LoggerFactory.getLogger(StateReclamationService.class);

    private final TokenStore store;
    private final CallerRateLimiter rateLimiter;
    private final Clock clock;
    private final AtomicBoolean sweeping = new AtomicBoolean(false);

    public StateReclamationService(TokenStore store, CallerRateLimiter rateLimiter, Clock clock) {
        this.store = store;
        this.rateLimiter = rateLimiter;
        this.clock = clock;
    }

    /**
     * Run one sweep. Concurrent invocations never overlap: if another sweep is
     * already in progress this returns {@code null}.
     */
    public CleanupReport purgeNow() {
        if (!sweeping.compareAndSet(false, true)) {
            log.info("decision=reclamation accepted=true basis=another_sweep_in_flight skipped=true");
            return null;
        }
        long startNanos = System.nanoTime();
        long at = clock.nowMillis();
        CleanupReport.Builder builder = CleanupReport.builder(at);
        try {
            sweepFamilies(at, builder);
            sweepOrphanTokens(at, builder);
            int idleKeys = rateLimiter.purgeIdleKeys(at);
            builder.add(CAT_IDLE_RATE_LIMIT_KEYS, idleKeys);

            CleanupReport report = builder.durationMillis((System.nanoTime() - startNanos) / 1_000_000L).build();
            log.info("decision=reclamation accepted=true basis=sweep_completed atMillis={} familiesScanned={} "
                            + "totalRemoved={} removedByCategory={} durationMillis={}",
                    report.atMillis(), report.familiesScanned(), report.totalRemoved(),
                    report.removedByCategory(), report.durationMillis());
            return report;
        } finally {
            sweeping.set(false);
        }
    }

    private void sweepFamilies(long at, CleanupReport.Builder builder) {
        Collection<String> familyIds = store.familyIds();
        builder.familiesScanned(familyIds.size());
        for (String familyId : familyIds) {
            store.withFamilyLock(familyId, fid -> {
                Session session = store.findSession(fid);
                if (session == null) {
                    return null;
                }
                String category = eligibleCategory(session, fid, at);
                if (category == null) {
                    return null;
                }
                Counts counts = countFamilyTokens(fid);
                int removed = store.removeFamilyFully(fid);
                builder.add(category, 1);
                builder.add(CAT_REFRESH_TOKENS, counts.refresh);
                builder.add(CAT_ACCESS_TOKENS, counts.access);
                log.info("decision=reclamation accepted=false callerId={} familyId={} tokenState=- "
                                + "reason=family_reclaimed basis={} refreshTokens={} accessTokens={} totalEntries={}",
                        session.getCallerId(), fid, category, counts.refresh, counts.access, removed);
                return null;
            });
        }
    }

    /**
     * Re-check eligibility <em>inside</em> the family lock. Returns the
     * category name when the family can never affect another decision, or
     * {@code null} when it must be retained.
     */
    private String eligibleCategory(Session session, String familyId, long at) {
        if (session.getStatus() == Session.Status.LOGGED_OUT
                || session.getStatus() == Session.Status.COMPROMISED) {
            return CAT_SESSION_TERMINAL;
        }
        // ACTIVE family: reclaimable only once no live credential remains.
        // Every refresh token must be expired AND every access token expired.
        boolean anyLiveRefresh = false;
        boolean anyLiveAccess = false;
        for (String key : store.refreshTokenKeys()) {
            RefreshTokenRecord r = store.findRefreshToken(key);
            if (r != null && familyId.equals(r.getFamilyId()) && r.getExpiresAtMillis() > at) {
                anyLiveRefresh = true;
                break;
            }
        }
        if (!anyLiveRefresh) {
            for (String key : store.accessTokenKeys()) {
                AccessTokenRecord a = store.findAccessToken(key);
                if (a != null && familyId.equals(a.getFamilyId()) && a.getExpiresAtMillis() > at) {
                    anyLiveAccess = true;
                    break;
                }
            }
        }
        return (!anyLiveRefresh && !anyLiveAccess) ? CAT_SESSION_EXPIRED : null;
    }

    private Counts countFamilyTokens(String familyId) {
        Counts counts = new Counts();
        for (String key : store.refreshTokenKeys()) {
            RefreshTokenRecord r = store.findRefreshToken(key);
            if (r != null && familyId.equals(r.getFamilyId())) {
                counts.refresh++;
            }
        }
        for (String key : store.accessTokenKeys()) {
            AccessTokenRecord a = store.findAccessToken(key);
            if (a != null && familyId.equals(a.getFamilyId())) {
                counts.access++;
            }
        }
        return counts;
    }

    /**
     * Remove token records whose family session is gone and whose own lifetime
     * has ended. They cannot prove anyone's identity nor trigger any replay
     * verdict. Tokens whose expiry is exactly {@code at} are expired and
     * removed (boundary inclusive).
     */
    private void sweepOrphanTokens(long at, CleanupReport.Builder builder) {
        List<String> deadRefresh = new ArrayList<>();
        for (String key : store.refreshTokenKeys()) {
            RefreshTokenRecord r = store.findRefreshToken(key);
            if (r != null && store.findSession(r.getFamilyId()) == null
                    && r.getExpiresAtMillis() <= at) {
                deadRefresh.add(key);
            }
        }
        for (String key : deadRefresh) {
            store.removeRefreshToken(key);
        }
        builder.add(CAT_ORPHAN_REFRESH, deadRefresh.size());

        List<String> deadAccess = new ArrayList<>();
        for (String key : store.accessTokenKeys()) {
            AccessTokenRecord a = store.findAccessToken(key);
            if (a != null && store.findSession(a.getFamilyId()) == null
                    && a.getExpiresAtMillis() <= at) {
                deadAccess.add(key);
            }
        }
        for (String key : deadAccess) {
            store.removeAccessToken(key);
        }
        builder.add(CAT_ORPHAN_ACCESS, deadAccess.size());
    }

    private static final class Counts {
        int refresh;
        int access;
    }
}
