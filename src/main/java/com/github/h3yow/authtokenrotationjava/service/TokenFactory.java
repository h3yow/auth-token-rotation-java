package com.github.h3yow.authtokenrotationjava.service;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

/** Issues opaque, URL-safe, high-entropy token strings. */
@Component
public class TokenFactory {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private final SecureRandom secureRandom = new SecureRandom();

    /** @return a freshly generated opaque token with the given prefix. */
    public String newToken(String prefix) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return prefix + "_" + ENCODER.encodeToString(bytes);
    }
}
