package com.github.h3yow.authtokenrotationjava.security;

import com.github.h3yow.authtokenrotationjava.domain.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
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
 * 受保护资源（/api/**）按令牌绑定的调用方身份限流。
 *
 * <p>排在鉴权过滤器之后：仅当请求已通过令牌鉴权时才执行，限流维度取自
 * 服务端 {@link AuthService.AuthenticatedCaller#clientId()}，不同调用方互不影响。</p>
 */
@Component
@Order(30)
public class ApiRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ApiRateLimitFilter.class);

    private final ClientRateLimiter rateLimiter;

    public ApiRateLimitFilter(ClientRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Object attribute = request.getAttribute(AccessTokenAuthenticationFilter.CALLER_ATTRIBUTE);
        if (!(attribute instanceof AuthService.AuthenticatedCaller caller)) {
            // 理论上不会到达：未鉴权请求已在前一个过滤器终止
            FilterResponses.writeError(response, AuthErrorCode.ACCESS_TOKEN_MISSING);
            return;
        }
        if (!rateLimiter.tryAcquire(caller.clientId())) {
            log.warn("资源接口限流命中 | clientId={} | sessionId={} | uri={} | 判定依据=该调用方滑动窗口计数已达上限",
                    caller.clientId(), caller.sessionId(), request.getRequestURI());
            FilterResponses.writeError(response, AuthErrorCode.RATE_LIMITED);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
