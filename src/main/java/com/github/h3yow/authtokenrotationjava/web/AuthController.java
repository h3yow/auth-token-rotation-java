package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.domain.AccessVerification;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** HTTP surface for login, refresh rotation, logout and a protected resource. */
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

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request,
                               @RequestHeader(RateLimitInterceptor.CALLER_HEADER) String callerId) {
        return TokenResponse.from(authService.login(request.subject(), callerId));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request,
                                 @RequestHeader(RateLimitInterceptor.CALLER_HEADER) String callerId) {
        return TokenResponse.from(authService.rotate(request.refreshToken(), callerId));
    }

    @PostMapping("/logout")
    public ResourceResponse logout(@RequestBody RefreshRequest request,
                                   @RequestHeader(RateLimitInterceptor.CALLER_HEADER) String callerId) {
        authService.logout(request.refreshToken(), callerId);
        return new ResourceResponse("logged_out", null, callerId, null, "session_revoked");
    }

    @PostMapping("/resource")
    public ResourceResponse resource(HttpServletRequest request,
                                     @RequestHeader(RateLimitInterceptor.CALLER_HEADER) String callerId) {
        String header = request.getHeader("Authorization");
        String token = null;
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring("Bearer ".length());
        }
        AccessVerification verification = authService.verifyAccessToken(token, callerId);
        if (!verification.accepted()) {
            // The service has already logged the detailed decision; translating
            // it to an AuthException lets the shared advice build one JSON shape.
            throw new com.github.h3yow.authtokenrotationjava.service.AuthException(
                    com.github.h3yow.authtokenrotationjava.service.AuthErrorCode
                            .valueOfCode(verification.reason()),
                    callerId, verification.familyId(), verification.tokenState(),
                    "access token verification failed: " + verification.reason());
        }
        return new ResourceResponse("ok", verification.subject(), callerId,
                verification.familyId(), verification.reason());
    }
}
