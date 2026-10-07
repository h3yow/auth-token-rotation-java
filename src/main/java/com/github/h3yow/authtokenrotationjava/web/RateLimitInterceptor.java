package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.identity.CallerIdentity;
import com.github.h3yow.authtokenrotationjava.identity.CallerIdentityResolver;
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
 * Enforces per-caller rate limits using a <b>server-confirmed</b> caller
 * identity. Billing never trusts the self-declared {@code X-Caller-Id} header
 * on credential-bearing endpoints: the presented access/refresh credential
 * must prove ownership first, and untrusted/forged/invalid requests are
 * rejected without touching any real caller's quota.
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    public static final String CALLER_HEADER = "X-Caller-Id";
    public static final String IDENTITY_ATTRIBUTE = "auth.callerIdentity";
    private static final Logger log = LoggerFactory.getLogger(RateLimitInterceptor.class);

    private final CallerRateLimiter rateLimiter;
    private final CallerIdentityResolver identityResolver;

    public RateLimitInterceptor(CallerRateLimiter rateLimiter,
                                CallerIdentityResolver identityResolver) {
        this.rateLimiter = rateLimiter;
        this.identityResolver = identityResolver;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String callerId = request.getHeader(CALLER_HEADER);
        String path = request.getRequestURI();
        CallerIdentity identity;

        if (isIssuancePath(path)) {
            // No credential exists yet: a missing header is its own 400; a
            // present header is billed in the isolated ISSUANCE namespace.
            if (callerId == null || callerId.isBlank()) {
                log.warn("decision=rate_limit accepted=false callerId=null tokenState=- "
                        + "reason=caller_identity_missing basis=header_X_Caller_Id_absent path={}", path);
                throw new AuthException(AuthErrorCode.CALLER_IDENTITY_MISSING, null, null, "-",
                        "missing caller identity header " + CALLER_HEADER);
            }
            identity = identityResolver.resolveIssuanceRequest(callerId);
        } else {
            String kind = credentialKind(path);
            String credential = extractCredential(request, kind);
            identity = identityResolver.resolveCredentialRequest(callerId, credential, kind);
            if (!identity.trusted()) {
                // Forgery / unknown credential / mismatched owner: rejected
                // before billing, so no real caller's quota is consumed.
                log.warn("decision=rate_limit accepted=false callerId={} tokenState=- "
                                + "reason=caller_identity_untrusted basis={} path={}",
                        String.valueOf(callerId), identity.basis(), path);
                throw new AuthException(AuthErrorCode.CALLER_IDENTITY_UNTRUSTED, callerId,
                        identity.familyId(), "-",
                        "caller identity not proven by a server-side credential: " + identity.basis());
            }
        }

        RateLimitDecision decision = rateLimiter.checkAndRegister(identity.rateLimitKey());
        if (!decision.allowed()) {
            log.warn("decision=rate_limit accepted=false callerId={} scope={} tokenState=- reason={} "
                            + "basis=sliding_window count={} limit={} window=[{},{}] windowMs={} provenBy={}",
                    identity.confirmedCallerId(), decision.scope(),
                    AuthErrorCode.RATE_LIMIT_EXCEEDED.code(),
                    decision.requestCountInWindow(), decision.limit(),
                    decision.windowStartMillis(), decision.windowEndMillis(), decision.windowMillis(),
                    identity.basis());
            throw new AuthException(AuthErrorCode.RATE_LIMIT_EXCEEDED, identity.confirmedCallerId(),
                    identity.familyId(), "-",
                    "rate limit exceeded: " + decision.requestCountInWindow()
                            + " requests in the last " + decision.windowMillis() + "ms, limit is "
                            + decision.limit());
        }
        request.setAttribute(IDENTITY_ATTRIBUTE, identity);
        log.debug("decision=rate_limit accepted=true callerId={} scope={} basis={}",
                identity.confirmedCallerId(), decision.scope(), identity.basis());
        return true;
    }

    private boolean isIssuancePath(String path) {
        return path != null && path.endsWith("/login");
    }

    private String credentialKind(String path) {
        if (path != null && path.endsWith("/resource")) {
            return CallerIdentityResolver.KIND_ACCESS;
        }
        // refresh and logout carry a refresh token in the JSON body
        return CallerIdentityResolver.KIND_REFRESH;
    }

    private String extractCredential(HttpServletRequest request, String kind) {
        if (CallerIdentityResolver.KIND_ACCESS.equals(kind)) {
            return CallerIdentityResolver.bearerToken(request.getHeader("Authorization"));
        }
        if (request instanceof CachedBodyHttpServletRequest cached) {
            return CallerIdentityResolver.refreshTokenFromJson(cached.getCachedBodyAsString());
        }
        return CallerIdentityResolver.refreshTokenFromJson(null);
    }
}
