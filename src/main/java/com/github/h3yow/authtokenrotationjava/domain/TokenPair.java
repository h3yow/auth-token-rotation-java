package com.github.h3yow.authtokenrotationjava.domain;

/** An access/refresh token pair returned by login and refresh. */
public record TokenPair(
        String accessToken,
        String refreshToken,
        String familyId,
        long accessTokenExpiresAtMillis,
        long refreshTokenExpiresAtMillis) {
}
