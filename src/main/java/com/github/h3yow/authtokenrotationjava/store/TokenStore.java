package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;

import java.util.Collection;
import java.util.function.Consumer;
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

    /** Run an action while holding the family's exclusive lock. */
    <T> T withFamilyLock(String familyId, Function<String, T> action);

    /** Invoke the consumer once per stored session (used by tests/ops). */
    void forEachSession(Consumer<Session> consumer);

    // ---- reclamation support ----------------------------------------------

    /** Snapshot of all known family ids. */
    Collection<String> familyIds();

    /** All opaque refresh-token keys currently stored. */
    Collection<String> refreshTokenKeys();

    /** All opaque access-token keys currently stored. */
    Collection<String> accessTokenKeys();

    /** Remove one session record. */
    void removeSession(String familyId);

    /** Remove one refresh-token record. */
    void removeRefreshToken(String opaqueToken);

    /** Remove one access-token record. */
    void removeAccessToken(String opaqueToken);

    /**
     * Remove every refresh and access token belonging to the family, the
     * session itself and the family's lock object. Must be invoked while
     * holding the family lock.
     *
     * @return number of token records removed
     */
    int removeFamilyFully(String familyId);
}
