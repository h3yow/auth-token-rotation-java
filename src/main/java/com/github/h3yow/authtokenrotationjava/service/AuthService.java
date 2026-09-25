package com.github.h3yow.authtokenrotationjava.service;

import com.github.h3yow.authtokenrotationjava.domain.TokenPair;

/**
 * 令牌签发、轮换、撤销与鉴权核心服务（骨架）。
 */
public interface AuthService {

    TokenPair issue(String clientId, String username, String password);

    TokenPair rotate(String clientId, String refreshToken);

    void logout(String clientId, String accessToken);

    /**
     * 校验访问令牌，返回调用方与用户信息；任何失败都以可区分原因抛出 AuthException。
     */
    AuthenticatedCaller authenticate(String accessToken);

    record AuthenticatedCaller(String clientId, String username, String sessionId) {
    }
}
