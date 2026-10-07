package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.config.SecurityProperties;
import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.identity.CallerIdentity;
import com.github.h3yow.authtokenrotationjava.identity.CallerIdentityResolver;
import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitScope;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.service.TokenFactory;
import com.github.h3yow.authtokenrotationjava.store.InMemoryTokenStore;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the server-side identity trust boundary. A request is
 * billable only when a server-side credential proves the declared caller.
 */
class CallerIdentityResolverTest {

    private MutableClock clock;
    private InMemoryTokenStore store;
    private AuthService authService;
    private CallerIdentityResolver resolver;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        store = new InMemoryTokenStore();
        SecurityProperties properties = new SecurityProperties();
        authService = new AuthService(store, new TokenFactory(), properties, clock);
        resolver = new CallerIdentityResolver(store);
    }

    @Test
    @DisplayName("valid access credential with matching header proves the owner and bills his AUTHENTICATED bucket")
    void validAccessCredentialIsTrusted() {
        TokenPair pair = authService.login("alice", "caller-A");
        CallerIdentity identity = resolver.resolveCredentialRequest(
                "caller-A", pair.accessToken(), CallerIdentityResolver.KIND_ACCESS);
        assertTrue(identity.trusted());
        assertEquals("caller-A", identity.confirmedCallerId());
        assertEquals(RateLimitScope.AUTHENTICATED, identity.rateLimitKey().scope());
        assertEquals("caller-A", identity.rateLimitKey().identity());
        System.out.printf("[identity] declared=caller-A proven=caller-A trusted=true basis=%s%n",
                identity.basis());
    }

    @Test
    @DisplayName("forged header on another caller's access credential is untrusted and bills nobody")
    void forgedHeaderIsUntrustedAndBillableToNobody() {
        TokenPair victim = authService.login("victim", "caller-A");
        CallerIdentity identity = resolver.resolveCredentialRequest(
                "caller-EVIL", victim.accessToken(), CallerIdentityResolver.KIND_ACCESS);
        assertFalse(identity.trusted());
        assertNull(identity.rateLimitKey(), "a forgery must not be billable to any bucket");
        assertNull(identity.confirmedCallerId());
        System.out.printf("[identity] declared=caller-EVIL owner=caller-A trusted=false basis=%s%n",
                identity.basis());
    }

    @Test
    @DisplayName("unknown or missing credentials are untrusted and bill nobody")
    void unknownAndMissingCredentialsAreUntrusted() {
        CallerIdentity unknown = resolver.resolveCredentialRequest(
                "caller-A", "atk_does_not_exist", CallerIdentityResolver.KIND_ACCESS);
        assertFalse(unknown.trusted());
        assertNull(unknown.rateLimitKey());

        CallerIdentity missing = resolver.resolveCredentialRequest(
                "caller-A", null, CallerIdentityResolver.KIND_REFRESH);
        assertFalse(missing.trusted());
        assertNull(missing.rateLimitKey());

        CallerIdentity unknownRefresh = resolver.resolveCredentialRequest(
                "caller-A", "rtk_nope", CallerIdentityResolver.KIND_REFRESH);
        assertFalse(unknownRefresh.trusted());
        assertNull(unknownRefresh.rateLimitKey());
        System.out.printf("[identity] unknown/missing credentials untrusted: %s | %s | %s%n",
                unknown.basis(), missing.basis(), unknownRefresh.basis());
    }

    @Test
    @DisplayName("an expired credential still proves ownership (billed), validity is decided downstream")
    void expiredCredentialStillProvesOwnership() {
        TokenPair pair = authService.login("bob", "caller-B");
        clock.advanceMillis(300_001); // access token expired, but ownership never changes
        CallerIdentity identity = resolver.resolveCredentialRequest(
                "caller-B", pair.accessToken(), CallerIdentityResolver.KIND_ACCESS);
        assertTrue(identity.trusted(), "expiry does not erase ownership");
        assertEquals("caller-B", identity.confirmedCallerId());
        System.out.printf("[identity] expired credential still trusted for billing basis=%s%n",
                identity.basis());
    }

    @Test
    @DisplayName("issuance requests live in an isolated ISSUANCE namespace, never in an owner's AUTHENTICATED bucket")
    void issuanceUsesIsolatedNamespace() {
        CallerIdentity issuance = resolver.resolveIssuanceRequest("caller-A");
        assertTrue(issuance.trusted());
        assertEquals(RateLimitScope.ISSUANCE, issuance.rateLimitKey().scope());
        CallerIdentity authenticated = resolver.resolveIssuanceRequest("caller-A");
        assertEquals(RateLimitScope.ISSUANCE, authenticated.rateLimitKey().scope());
        System.out.println("[identity] issuance namespace isolated from AUTHENTICATED owner buckets");
    }
}
