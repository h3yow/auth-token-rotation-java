package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.ratelimit.CallerRateLimiter;
import com.github.h3yow.authtokenrotationjava.ratelimit.CallerIdentityGate;
import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitDecision;
import com.github.h3yow.authtokenrotationjava.service.AuthErrorCode;
import com.github.h3yow.authtokenrotationjava.service.AuthException;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.service.TokenFactory;
import com.github.h3yow.authtokenrotationjava.store.InMemoryTokenStore;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Trust-boundary unit tests. The quota key is the server-attested credential
 * owner, so a forged header or an invalid credential can never move a real
 * caller's window; the distinct rejection codes stay observable.
 */
class CallerIdentityGateTest {

    private MutableClock clock;
    private CallerRateLimiter limiter;
    private CallerIdentityGate gate;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setRateLimitMaxRequests(5);
        properties.setRateLimitWindowMillis(1_000);
        properties.setAccessTokenTtlMillis(300_000);
        properties.setRefreshTokenTtlMillis(3_600_000);
        TokenStore store = new InMemoryTokenStore();
        limiter = new CallerRateLimiter(properties, clock);
        gate = new CallerIdentityGate(limiter, store);
        authService = new AuthService(store, new TokenFactory(), properties, clock);
    }

    private AuthErrorCode codeOf(Runnable r) {
        return assertThrows(AuthException.class, r::run).getErrorCode();
    }

    @Test
    @DisplayName("forged header with a real token charges the token owner, never the declared caller")
    void forgedHeaderChargesTokenOwnerNotDeclared() {
        TokenPair victim = authService.login("vic", "caller-victim");
        TokenPair attacker = authService.login("att", "caller-attacker");

        // Attacker presents its OWN valid token but declares the victim. The
        // gate admits it 5 times (the header-vs-owner mismatch is decided later
        // by AuthService), and every charge lands on the attested OWNER.
        for (int i = 0; i < 5; i++) {
            gate.chargeAccess(attacker.accessToken(), "caller-victim");
        }
        // Attacker's own bucket is now saturated (charged as owner)...
        assertEquals(AuthErrorCode.RATE_LIMIT_EXCEEDED,
                assertThrows(AuthException.class,
                        () -> gate.chargeAccess(attacker.accessToken(), "caller-victim")).getErrorCode());

        // ...while the victim's trusted window is completely untouched.
        for (int i = 0; i < 5; i++) {
            RateLimitDecision d = limiter.checkAndRegister(CallerRateLimiter.Tier.TRUSTED, "caller-victim");
            assertTrue(d.allowed(), "victim quota untouched by header spoofing, admission " + (i + 1));
        }
        // Sanity: the victim token really is owned by the victim.
        assertTrue(victim.accessToken() != null);
        System.out.println("[trust-boundary] spoof=attacker-owner-charged-5x+1x429 victimWindowAfterSpoof=5/5-free");
    }

    @Test
    @DisplayName("invalid credentials are rejected with distinct codes and never charge a real caller")
    void invalidCredentialsDoNotChargeRealCallers() {
        TokenPair victim = authService.login("vic", "caller-victim");

        assertEquals(AuthErrorCode.REFRESH_TOKEN_UNKNOWN,
                codeOf(() -> gate.chargeRefresh("rtk_garbage", "caller-victim")));
        assertEquals(AuthErrorCode.ACCESS_TOKEN_UNKNOWN,
                codeOf(() -> gate.chargeAccess("atk_garbage", "caller-victim")));
        assertEquals(AuthErrorCode.ACCESS_TOKEN_MISSING,
                codeOf(() -> gate.chargeAccess(null, "caller-victim")));
        assertEquals(AuthErrorCode.CALLER_IDENTITY_MISSING,
                codeOf(() -> gate.chargeRefresh(victim.refreshToken(), null)));

        for (int i = 0; i < 5; i++) {
            RateLimitDecision d = limiter.checkAndRegister(CallerRateLimiter.Tier.TRUSTED, "caller-victim");
            assertTrue(d.allowed(), "forged/invalid traffic must not consume victim quota, admission " + (i + 1));
        }
        System.out.println("[trust-boundary] forged=refresh_unknown+access_unknown+missing+identity_missing "
                + "victimWindowAfterForgery=5/5-free");
    }

    @Test
    @DisplayName("login entry point uses the unauthenticated bucket and cannot spend a real caller quota")
    void loginUsesUnauthenticatedBucket() {
        for (int i = 0; i < 5; i++) {
            gate.chargeUnauthenticated("caller-login-" + i, "login");
        }
        assertEquals(AuthErrorCode.RATE_LIMIT_EXCEEDED,
                codeOf(() -> gate.chargeUnauthenticated("caller-login-extra", "login")));

        // A real caller's bucket is a separate namespace: unaffected.
        RateLimitDecision d = limiter.checkAndRegister(CallerRateLimiter.Tier.TRUSTED, "caller-victim");
        assertTrue(d.allowed());
        System.out.println("[trust-boundary] loginBucket=5xok+1x429 realCallerBucket=independent");
    }

    @Test
    @DisplayName("a missing identity at the login entry point is a distinct 400 and charges nothing")
    void missingIdentityChargesNothing() {
        assertEquals(AuthErrorCode.CALLER_IDENTITY_MISSING,
                codeOf(() -> gate.chargeUnauthenticated(null, "login")));
        // Repeated attempts with a present identity still get their full window,
        // proving the missing-identity rejection was never registered.
        for (int i = 0; i < 5; i++) {
            gate.chargeUnauthenticated("caller-present", "login");
        }
        System.out.println("[trust-boundary] missingIdentity=400 unauthBucketAfterMissing=5/5-free");
    }

    @Test
    @DisplayName("a flood of forged credentials is bounded by the untrusted bucket but still cannot reach a real caller")
    void untrustedFloodIsBoundedSeparately() {
        for (int i = 0; i < 5; i++) {
            final int n = i;
            assertEquals(AuthErrorCode.ACCESS_TOKEN_UNKNOWN,
                    codeOf(() -> gate.chargeAccess("atk_forged_" + n, "caller-victim")));
        }
        // 6th forged request hits the shared untrusted bucket's limit...
        assertEquals(AuthErrorCode.RATE_LIMIT_EXCEEDED,
                codeOf(() -> gate.chargeAccess("atk_forged_6", "caller-victim")));
        // ...yet the real victim still has its full trusted window.
        for (int i = 0; i < 5; i++) {
            RateLimitDecision d = limiter.checkAndRegister(CallerRateLimiter.Tier.TRUSTED, "caller-victim");
            assertTrue(d.allowed(), "untrusted flood never consumed victim quota, admission " + (i + 1));
        }
        System.out.println("[trust-boundary] untrustedFlood=5xunknown+1x429 victimWindow=5/5-free");
    }
}
