package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;

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

    /**
     * Attempt to acquire the single-attempt gate for a family. Returns
     * {@code true} for exactly one concurrent caller; a second concurrent
     * caller receives {@code false} without blocking. The gate is released by
     * the holder in {@link #releaseFamilyGate}.
     */
    boolean tryAcquireFamilyGate(String familyId, String attemptId);

    void releaseFamilyGate(String familyId, String attemptId);

    /** Run an action while holding the family's exclusive lock. */
    <T> T withFamilyLock(String familyId, Function<String, T> action);

    /** Invoke the consumer once per stored session (used by tests/ops). */
    void forEachSession(Consumer<Session> consumer);
}
