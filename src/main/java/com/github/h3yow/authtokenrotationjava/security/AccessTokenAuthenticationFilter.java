package com.github.h3yow.authtokenrotationjava.security;

import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 受保护资源（/api/**）的访问令牌鉴权过滤器。
 *
 * <p>鉴权先于限流执行：调用方身份直接取自服务端令牌绑定关系，调用方无法通过
 * 伪造 {@code X-Client-Id} 影响限流维度或冒充他人。任何失败都由服务端给出
 * 可区分原因（缺失/未知/过期/会话撤销）。</p>
 */
@Component
@Order(20)
public class AccessTokenAuthenticationFilter extends OncePerRequestFilter {

    /** 鉴权通过后挂在请求上的调用方信息属性名。 */
    public static final String CALLER_ATTRIBUTE = "auth.caller";

    private final AuthService authService;

    public AccessTokenAuthenticationFilter(AuthService authService) {
        this.authService = authService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = extractBearer(request);
        if (token == null) {
            boolean headerPresent = request.getHeader("Authorization") != null;
            FilterResponses.writeError(response, headerPresent
                    ? AuthErrorCode.ACCESS_TOKEN_UNKNOWN
                    : AuthErrorCode.ACCESS_TOKEN_MISSING);
            return;
        }
        try {
            AuthService.AuthenticatedCaller caller = authService.authenticate(token);
            request.setAttribute(CALLER_ATTRIBUTE, caller);
        } catch (AuthException ex) {
            FilterResponses.writeError(response, ex.getErrorCode());
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static String extractBearer(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            return null;
        }
        String trimmed = header.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = trimmed.substring(7).trim();
            return token.isEmpty() ? null : token;
        }
        String raw = trimmed;
        return raw.isEmpty() ? null : raw;
    }
}
