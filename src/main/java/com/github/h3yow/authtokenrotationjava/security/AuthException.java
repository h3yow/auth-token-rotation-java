package com.github.h3yow.authtokenrotationjava.security;

import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;

/**
 * 鉴权/限流失败异常，携带稳定、可区分的 {@link AuthErrorCode}。
 */
public class AuthException extends RuntimeException {

    private final AuthErrorCode errorCode;

    public AuthException(AuthErrorCode errorCode) {
        super(errorCode.name() + ": " + errorCode.getDescription());
        this.errorCode = errorCode;
    }

    public AuthErrorCode getErrorCode() {
        return errorCode;
    }
}
