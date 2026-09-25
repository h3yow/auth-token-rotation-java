package com.github.h3yow.authtokenrotationjava.security;

import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.ClientRateLimiter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 鉴权端点（/auth/**）按 {@code X-Client-Id} 维度限流。
 *
 * <p>登录/刷新/注销接口尚未持有服务端可验证的调用方身份，因此以调用方
 * 自报的 {@code X-Client-Id} 作为限流维度；缺失则拒绝。不同调用方各自独立计数。</p>
 */
@Component
@Order(10)
public class ClientRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ClientRateLimitFilter.class);

    private final ClientRateLimiter rateLimiter;

    public ClientRateLimitFilter(ClientRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String clientId = request.getHeader("X-Client-Id");
        if (clientId == null || clientId.isBlank()) {
            log.warn("限流前置校验拒绝 | uri={} | clientId=缺失 | 判定依据=缺少调用方标识");
            FilterResponses.writeError(response, AuthErrorCode.CLIENT_ID_MISSING);
            return;
        }
        if (!rateLimiter.tryAcquire(clientId)) {
            FilterResponses.writeError(response, AuthErrorCode.RATE_LIMITED);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
