package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;
import java.util.function.Function;

/** Concurrent in-memory implementation of {@link TokenStore}. */
@Component
public class InMemoryTokenStore implements TokenStore {

    private final ConcurrentMap<String, Session> sessions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, RefreshTokenRecord> refreshTokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, AccessTokenRecord> accessTokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Object> familyLocks = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> familyGates = new ConcurrentHashMap<>();

    @Override
    public void saveSession(Session session) {
        sessions.put(session.getFamilyId(), session);
    }

    @Override
    public Session findSession(String familyId) {
        return sessions.get(familyId);
    }

    @Override
    public void saveRefreshToken(String opaqueToken, RefreshTokenRecord record) {
        refreshTokens.put(opaqueToken, record);
    }

    @Override
    public RefreshTokenRecord findRefreshToken(String opaqueToken) {
        return refreshTokens.get(opaqueToken);
    }

    @Override
    public void saveAccessToken(String opaqueToken, AccessTokenRecord record) {
        accessTokens.put(opaqueToken, record);
    }

    @Override
    public AccessTokenRecord findAccessToken(String opaqueToken) {
        return accessTokens.get(opaqueToken);
    }

    @Override
    public boolean tryAcquireFamilyGate(String familyId, String attemptId) {
        // putIfAbsent is atomic: exactly one concurrent attempt wins the gate,
        // every overlapping attempt observes the winner and fails immediately.
        return familyGates.putIfAbsent(familyId, attemptId) == null;
    }

    @Override
    public void releaseFamilyGate(String familyId, String attemptId) {
        // Only the holder (identified by its unique attempt id) may clear the
        // gate, so an interleaving loser cannot remove the winner's gate.
        familyGates.remove(familyId, attemptId);
    }

    @Override
    public <T> T withFamilyLock(String familyId, Function<String, T> action) {
        Object lock = familyLocks.computeIfAbsent(familyId, key -> new Object());
        synchronized (lock) {
            return action.apply(familyId);
        }
    }

    @Override
    public void forEachSession(Consumer<Session> consumer) {
        sessions.values().forEach(consumer);
    }
}
