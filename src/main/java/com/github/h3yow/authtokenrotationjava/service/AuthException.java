package com.github.h3yow.authtokenrotationjava.service;

/**
 * Raised whenever an authentication or refresh decision is negative. Carries a
 * stable {@link AuthErrorCode} plus contextual metadata used in the response
 * body and in the decision log.
 */
public class AuthException extends RuntimeException {

    private final AuthErrorCode errorCode;
    private final String callerId;
    private final String familyId;
    private final String tokenState;

    public AuthException(AuthErrorCode errorCode, String callerId, String familyId,
                         String tokenState, String detail) {
        super(detail);
        this.errorCode = errorCode;
        this.callerId = callerId;
        this.familyId = familyId;
        this.tokenState = tokenState;
    }

    public AuthErrorCode getErrorCode() {
        return errorCode;
    }

    public String getCallerId() {
        return callerId;
    }

    public String getFamilyId() {
        return familyId;
    }

    public String getTokenState() {
        return tokenState;
    }
}
