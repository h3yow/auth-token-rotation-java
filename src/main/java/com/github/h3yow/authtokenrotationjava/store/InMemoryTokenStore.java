package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenEntry;
import com.github.h3yow.authtokenrotationjava.domain.TokenFamily;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/**
 * 进程内并发令牌存储。
 *
 * <p>每条刷新链路（family）通过 {@link ConcurrentHashMap#compute} 获得
 * per-key 原子性：轮换、重放判定、撤销等"读-判-写"在该 family 的锁段内
 * 一次完成，因此同一刷新令牌的并发刷新只有一个线程能看到"当前令牌"并完成轮换。
 * 不同 family 之间互不阻塞，合法会话不会被其他链路的竞争误伤。</p>
 */
@Component
public class InMemoryTokenStore implements TokenStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryTokenStore.class);

    private final ConcurrentMap<String, TokenFamily> families = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, AccessTokenEntry> accessTokens = new ConcurrentHashMap<>();

    @Override
    public <T> T withFamilyLock(String familyId, Function<TokenFamily, T> rotateFunction) {
        // 每次调用独立的栈封闭结果容器，无线程本地残留；
        // compute 保证针对同一 familyId 的"读-判-写"在同一锁段内原子完成。
        Object[] resultBox = new Object[1];
        families.compute(familyId, (id, family) -> {
            if (family != null) {
                resultBox[0] = rotateFunction.apply(family);
            }
            return family;
        });
        @SuppressWarnings("unchecked")
        T result = (T) resultBox[0];
        return result;
    }

    @Override
    public void saveFamily(TokenFamily family) {
        families.put(family.getFamilyId(), family);
    }

    @Override
    public TokenFamily findFamily(String familyId) {
        return families.get(familyId);
    }

    @Override
    public AccessTokenEntry saveAccess(AccessTokenEntry entry) {
        accessTokens.put(entry.getTokenId(), entry);
        return entry;
    }

    @Override
    public AccessTokenEntry findAccess(String tokenId) {
        return accessTokens.get(tokenId);
    }

    @Override
    public Collection<AccessTokenEntry> revokeAccessTokensByFamily(String familyId, String reason) {
        List<AccessTokenEntry> revoked = new ArrayList<>();
        accessTokens.values().removeIf(entry -> {
            boolean belongs = entry.getFamilyId().equals(familyId);
            if (belongs && !entry.isRevoked()) {
                entry.markRevoked();
                revoked.add(entry);
                log.info("访问令牌已撤销 | familyId={} | tokenId={} | clientId={} | 依据={}",
                        familyId, entry.getTokenId(), entry.getClientId(), reason);
            }
            return false;
        });
        return revoked;
    }

}
