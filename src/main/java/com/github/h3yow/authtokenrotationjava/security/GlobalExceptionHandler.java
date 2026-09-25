package com.github.h3yow.authtokenrotationjava.security;

import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 将可区分的鉴权失败原因翻译成稳定的 HTTP 响应。
 *
 * <p>响应体固定包含 {@code error}（机器可判定的稳定错误码）与
 * {@code reason}（人类可读的判定依据），便于测试与调用方稳定复现结论。</p>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuth(AuthException ex) {
        AuthErrorCode code = ex.getErrorCode();
        HttpStatus status = code == AuthErrorCode.RATE_LIMITED ? HttpStatus.TOO_MANY_REQUESTS
                : HttpStatus.UNAUTHORIZED;
        return ResponseEntity.status(status).body(body(code));
    }

    @ExceptionHandler({MissingRequestHeaderException.class, HttpMessageNotReadableException.class,
            MethodArgumentNotValidException.class})
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
        AuthErrorCode code;
        if (ex instanceof MissingRequestHeaderException header
                && header.getHeaderName().equalsIgnoreCase("X-Client-Id")) {
            code = AuthErrorCode.CLIENT_ID_MISSING;
        } else if (ex instanceof MissingRequestHeaderException) {
            code = AuthErrorCode.ACCESS_TOKEN_MISSING;
        } else {
            code = AuthErrorCode.LOGIN_INVALID;
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body(code));
    }

    private static Map<String, Object> body(AuthErrorCode code) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code.name());
        body.put("reason", code.getDescription());
        body.put("timestamp", Instant.now().toString());
        return body;
    }
}
