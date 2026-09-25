package com.github.h3yow.authtokenrotationjava.web.dto;

import java.time.Instant;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String sessionId,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
}
