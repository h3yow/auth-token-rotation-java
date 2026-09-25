package com.github.h3yow.authtokenrotationjava.domain;

import java.time.Instant;

/**
 * 一次签发或轮换返回的令牌对。
 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        String sessionId,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
}
