package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.ratelimit.CallerIdentityGate;
import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.maintenance.ReclaimReport;
import com.github.h3yow.authtokenrotationjava.maintenance.StateReclaimer;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** HTTP surface for login, refresh rotation, logout, a protected resource and reclamation. */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    public record LoginRequest(String subject) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    public record TokenResponse(String accessToken, String refreshToken, String familyId,
                                long accessTokenExpiresAtMillis, long refreshTokenExpiresAtMillis) {
        static TokenResponse from(TokenPair pair) {
            return new TokenResponse(pair.accessToken(), pair.refreshToken(), pair.familyId(),
                    pair.accessTokenExpiresAtMillis(), pair.refreshTokenExpiresAtMillis());
        }
    }

    public record ResourceResponse(String status, String subject, String callerId,
                                   String familyId, String reason) {
    }

    private final AuthService authService;
    private final CallerIdentityGate identityGate;
    private final StateReclaimer reclaimer;

    public AuthController(AuthService authService, CallerIdentityGate identityGate,
                          StateReclaimer reclaimer) {
        this.authService = authService;
        this.identityGate = identityGate;
        this.reclaimer = reclaimer;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request,
                               @RequestHeader(value = RateLimitHeaders.CALLER_HEADER, required = false)
                               String callerId) {
        // No credential exists yet: charge the shared unauthenticated bucket,
        // never any real caller's quota. The header only labels the new session.
        identityGate.chargeUnauthenticated(callerId, "login");
        return TokenResponse.from(authService.login(request.subject(), callerId));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request,
                                 @RequestHeader(value = RateLimitHeaders.CALLER_HEADER, required = false)
                                 String callerId) {
        identityGate.chargeRefresh(request.refreshToken(), callerId);
        return TokenResponse.from(authService.rotate(request.refreshToken(), callerId));
    }

    @PostMapping("/logout")
    public ResourceResponse logout(@RequestBody RefreshRequest request,
                                   @RequestHeader(value = RateLimitHeaders.CALLER_HEADER, required = false)
                                   String callerId) {
        identityGate.chargeRefresh(request.refreshToken(), callerId);
        authService.logout(request.refreshToken(), callerId);
        return new ResourceResponse("logged_out", null, callerId, null, "session_revoked");
    }

    @PostMapping("/resource")
    public ResourceResponse resource(HttpServletRequest request,
                                     @RequestHeader(value = RateLimitHeaders.CALLER_HEADER, required = false)
                                     String callerId) {
        String token = bearerToken(request);
        identityGate.chargeAccess(token, callerId);
        AccessVerification verification = authService.verifyAccessToken(token, callerId);
        if (!verification.accepted()) {
            // The service has already logged the detailed decision; translating
            // it to an AuthException lets the shared advice build one JSON shape.
            throw new AuthException(AuthErrorCode.valueOfCode(verification.reason()),
                    callerId, verification.familyId(), verification.tokenState(),
                    "access token verification failed: " + verification.reason());
        }
        return new ResourceResponse("ok", verification.subject(), callerId,
                verification.familyId(), verification.reason());
    }

    /**
     * Trigger one safe reclamation sweep. Belongs to the unauthenticated ops
     * tier (it carries no caller credential) and therefore cannot consume any
     * real caller's quota.
     */
    @PostMapping("/maintenance/reclaim")
    public ReclaimReport reclaim(@RequestHeader(value = RateLimitHeaders.CALLER_HEADER, required = false)
                                 String callerId) {
        identityGate.chargeUnauthenticated(callerId, "reclaim");
        return reclaimer.reclaim();
    }

    private static String bearerToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring("Bearer ".length());
        }
        return null;
    }
}
