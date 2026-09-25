package com.github.h3yow.authtokenrotationjava.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 过滤器链中直接写出稳定错误响应的工具（过滤器异常不经过 ControllerAdvice）。
 */
final class FilterResponses {

    private static final Logger log = LoggerFactory.getLogger(FilterResponses.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private FilterResponses() {
    }

    static void writeError(HttpServletResponse response, AuthErrorCode code) throws IOException {
        int status = code == AuthErrorCode.RATE_LIMITED
                ? HttpStatus.TOO_MANY_REQUESTS.value()
                : HttpStatus.UNAUTHORIZED.value();
        if (!response.isCommitted()) {
            response.setStatus(status);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", code.name());
            body.put("reason", code.getDescription());
            body.put("timestamp", Instant.now().toString());
            response.getWriter().write(MAPPER.writeValueAsString(body));
        }
        log.debug("过滤器拒绝响应已写出 | error={} | httpStatus={}", code.name(), status);
    }
}
