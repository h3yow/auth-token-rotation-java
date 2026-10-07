package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;

import java.util.function.Function;

/**
 * Server-side token state store. All refresh-chain mutations for a family run
 * inside {@link #withFamilyLock} so rotation is atomic.
 */
public interface TokenStore {

    void saveSession(Session session);

    Session findSession(String familyId);

    void saveRefreshToken(String opaqueToken, RefreshTokenRecord record);

    RefreshTokenRecord findRefreshToken(String opaqueToken);

    void saveAccessToken(String opaqueToken, AccessTokenRecord record);

    AccessTokenRecord findAccessToken(String opaqueToken);

    /**
     * Token and owning-session snapshot taken atomically while holding the
     * family lock, so concurrent rotation/logout/reclaim can never make the two
     * observations disagree. Both elements may be {@code null} when absent.
     */
    record AccessSnapshot(AccessTokenRecord access, Session session) {
    }

    /**
     * Read an access token together with the session of its family inside the
     * family lock. Never returns {@code null}; members may be individually null.
     */
    AccessSnapshot snapshotAccessToken(String opaqueToken);

    /** Remove a single stored record; used by safe reclamation. */
    void removeSession(String familyId);

    void removeRefreshToken(String opaqueToken);

    void removeAccessToken(String opaqueToken);

    /** Snapshot all stored ids/records (used by safe reclamation). */
    java.util.List<java.util.Map.Entry<String, Session>> allSessions();

    java.util.List<java.util.Map.Entry<String, RefreshTokenRecord>> allRefreshTokens();

    java.util.List<java.util.Map.Entry<String, AccessTokenRecord>> allAccessTokens();

    /** Run an action while holding the family's exclusive lock. */
    <T> T withFamilyLock(String familyId, Function<String, T> action);
}
