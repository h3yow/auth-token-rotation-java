package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.ratelimit.CallerRateLimiter;
import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitDecision;
import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces per-caller rate limits before any authentication logic runs, so an
 * over-limit caller cannot probe the token machinery.
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    public static final String CALLER_HEADER = "X-Caller-Id";
    private static final Logger log = LoggerFactory.getLogger(RateLimitInterceptor.class);

    private final CallerRateLimiter rateLimiter;

    public RateLimitInterceptor(CallerRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String callerId = request.getHeader(CALLER_HEADER);
        if (callerId == null || callerId.isBlank()) {
            // The caller identity is the sole rate-limit dimension; an
            // anonymous caller cannot be isolated or counted, so it is rejected
            // with its own distinguishable basis.
            log.warn("decision=rate_limit accepted=false callerId=null tokenState=- "
                    + "reason=caller_identity_missing basis=header_X_Caller_Id_absent");
            throw new AuthException(AuthErrorCode.CALLER_IDENTITY_MISSING, null, null, "-",
                    "missing caller identity header " + CALLER_HEADER);
        }
        RateLimitDecision decision = rateLimiter.checkAndRegister(callerId);
        if (!decision.allowed()) {
            log.warn("decision=rate_limit accepted=false callerId={} tokenState=- reason={} "
                            + "basis=sliding_window count={} limit={} window=[{},{}] windowMs={}",
                    callerId, AuthErrorCode.RATE_LIMIT_EXCEEDED.code(),
                    decision.requestCountInWindow(), decision.limit(),
                    decision.windowStartMillis(), decision.windowEndMillis(), decision.windowMillis());
            throw new AuthException(AuthErrorCode.RATE_LIMIT_EXCEEDED, callerId, null, "-",
                    "rate limit exceeded: " + decision.requestCountInWindow()
                            + " requests in the last " + decision.windowMillis() + "ms, limit is "
                            + decision.limit());
        }
        log.debug("decision=rate_limit accepted=true callerId={} basis=sliding_window count={} limit={}",
                callerId, decision.requestCountInWindow(), decision.limit());
        return true;
    }
}
