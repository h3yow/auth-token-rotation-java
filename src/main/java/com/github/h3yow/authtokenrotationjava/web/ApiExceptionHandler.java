package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

/** Translates {@link AuthException} decisions into stable JSON responses. */
@RestControllerAdvice
public class ApiExceptionHandler {

    public record ErrorBody(String error, String message, String callerId, String familyId,
                            String tokenState, int httpStatus, String timestamp) {
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorBody> handleAuth(AuthException ex) {
        AuthErrorCode code = ex.getErrorCode();
        ErrorBody body = new ErrorBody(
                code.code(),
                ex.getMessage(),
                ex.getCallerId(),
                ex.getFamilyId(),
                ex.getTokenState(),
                code.httpStatus(),
                Instant.now().toString());
        return ResponseEntity.status(HttpStatus.valueOf(code.httpStatus())).body(body);
    }
}
