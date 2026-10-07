package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
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

    // ---- reclamation support ----------------------------------------------

    @Override
    public Collection<String> familyIds() {
        return List.copyOf(sessions.keySet());
    }

    @Override
    public Collection<String> refreshTokenKeys() {
        return List.copyOf(refreshTokens.keySet());
    }

    @Override
    public Collection<String> accessTokenKeys() {
        return List.copyOf(accessTokens.keySet());
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
    public int removeFamilyFully(String familyId) {
        int removed = 0;
        removed += removeByFamily(refreshTokens, familyId);
        removed += removeByFamily(accessTokens, familyId);
        sessions.remove(familyId);
        // No request can be holding a lock for a family that is fully dead
        // (eligibility was re-checked under this very lock), so removing the
        // lock object can never split later traffic across two monitors.
        familyLocks.remove(familyId);
        return removed;
    }

    private <T> int removeByFamily(ConcurrentMap<String, T> map, String familyId) {
        int[] removed = {0};
        map.entrySet().removeIf(entry -> {
            String entryFamily = familyOf(entry.getValue());
            if (familyId.equals(entryFamily)) {
                removed[0]++;
                return true;
            }
            return false;
        });
        return removed[0];
    }

    private String familyOf(Object record) {
        if (record instanceof RefreshTokenRecord r) {
            return r.getFamilyId();
        }
        if (record instanceof AccessTokenRecord a) {
            return a.getFamilyId();
        }
        return null;
    }
}
