package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/** Concurrent in-memory implementation of {@link TokenStore}. */
@Component
public class InMemoryTokenStore implements TokenStore {

    private final ConcurrentMap<String, Session> sessions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, RefreshTokenRecord> refreshTokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, AccessTokenRecord> accessTokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Object> familyLocks = new ConcurrentHashMap<>();

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
    public AccessSnapshot snapshotAccessToken(String opaqueToken) {
        AccessTokenRecord record = accessTokens.get(opaqueToken);
        if (record == null) {
            return new AccessSnapshot(null, null);
        }
        Object lock = familyLocks.computeIfAbsent(record.getFamilyId(), key -> new Object());
        synchronized (lock) {
            return new AccessSnapshot(accessTokens.get(opaqueToken), sessions.get(record.getFamilyId()));
        }
    }

    @Override
    public void removeSession(String familyId) {
        sessions.remove(familyId);
    }

    @Override
    public void removeRefreshToken(String opaqueToken) {
        refreshTokens.remove(opaqueToken);
    }

    @Override
    public void removeAccessToken(String opaqueToken) {
        accessTokens.remove(opaqueToken);
    }

    @Override
    public java.util.List<java.util.Map.Entry<String, Session>> allSessions() {
        return new java.util.ArrayList<>(sessions.entrySet());
    }

    @Override
    public java.util.List<java.util.Map.Entry<String, RefreshTokenRecord>> allRefreshTokens() {
        return new java.util.ArrayList<>(refreshTokens.entrySet());
    }

    @Override
    public java.util.List<java.util.Map.Entry<String, AccessTokenRecord>> allAccessTokens() {
        return new java.util.ArrayList<>(accessTokens.entrySet());
    }

    @Override
    public <T> T withFamilyLock(String familyId, Function<String, T> action) {
        Object lock = familyLocks.computeIfAbsent(familyId, key -> new Object());
        synchronized (lock) {
            return action.apply(familyId);
        }
    }
}
