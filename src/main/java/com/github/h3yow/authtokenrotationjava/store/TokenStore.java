package com.github.h3yow.authtokenrotationjava.store;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenEntry;
import com.github.h3yow.authtokenrotationjava.domain.TokenFamily;

import java.util.Collection;
import java.util.function.Function;

/**
 * 令牌与刷新链路的存储抽象（当前实现为进程内并发存储）。
 */
public interface TokenStore {

    /**
     * 以 family 维度加锁，原子执行轮换操作。
     * 返回操作函数对 {@link TokenFamily} 的计算结果。
     */
    <T> T withFamilyLock(String familyId, Function<TokenFamily, T> rotateFunction);

    void saveFamily(TokenFamily family);

    TokenFamily findFamily(String familyId);

    AccessTokenEntry saveAccess(AccessTokenEntry entry);

    AccessTokenEntry findAccess(String tokenId);

    /**
     * 撤销某条刷新链路上所有尚未过期的访问令牌，返回被撤销的条目。
     */
    Collection<AccessTokenEntry> revokeAccessTokensByFamily(String familyId, String reason);
}
