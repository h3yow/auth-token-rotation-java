package com.github.h3yow.authtokenrotationjava.identity;

import com.github.h3yow.authtokenrotationjava.domain.AccessTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.RefreshTokenRecord;
import com.github.h3yow.authtokenrotationjava.domain.Session;
import com.github.h3yow.authtokenrotationjava.ratelimit.RateLimitKey;
import com.github.h3yow.authtokenrotationjava.store.TokenStore;
import org.springframework.stereotype.Component;

/**
 * Resolves the billing identity of an HTTP request from <em>server-side</em>
 * credential state rather than from the self-declared {@code X-Caller-Id}
 * header.
 *
 * <p>Trust boundary:
 * <ul>
 *   <li>A request carrying an access/refresh credential that the server
 *       actually has on record proves the owner of that credential. It is
 *       billed to the owner's AUTHENTICATED bucket, and only if the declared
 *       header matches the owner does it proceed; otherwise it is untrusted
 *       and consumes nobody's quota.</li>
 *   <li>Expiry/revocation of a credential does not change its ownership, so an
 *       expired credential still proves identity (the request is billed and
 *       then rejected downstream with its precise validity reason).</li>
 *   <li>The credential-less issuance endpoint can prove nothing; its requests
 *       are billed to isolated ISSUANCE buckets keyed by the raw header.</li>
 * </ul>
 */
@Component
public class CallerIdentityResolver {

    public static final String KIND_ACCESS = "access";
    public static final String KIND_REFRESH = "refresh";

    private final TokenStore store;

    public CallerIdentityResolver(TokenStore store) {
        this.store = store;
    }

    /**
     * Resolve identity for a credential-bearing endpoint (refresh / logout /
     * resource).
     *
     * @param declaredCallerId raw {@code X-Caller-Id} value, may be null
     * @param credential       opaque token presented by the caller, may be null
     * @param kind             {@link #KIND_ACCESS} or {@link #KIND_REFRESH}
     */
    public CallerIdentity resolveCredentialRequest(String declaredCallerId, String credential, String kind) {
        if (credential == null || credential.isBlank()) {
            return untrusted(declaredCallerId,
                    "no_" + kind + "_credential_presented");
        }
        String confirmedCaller;
        String familyId;
        String tokenState;
        if (KIND_ACCESS.equals(kind)) {
            AccessTokenRecord record = store.findAccessToken(credential);
            if (record == null) {
                return untrusted(declaredCallerId, "access_token_unknown_server_side");
            }
            confirmedCaller = record.getCallerId();
            familyId = record.getFamilyId();
            tokenState = record.isRevoked() ? "REVOKED" : "RECORDED";
        } else {
            RefreshTokenRecord record = store.findRefreshToken(credential);
            if (record == null) {
                return untrusted(declaredCallerId, "refresh_token_unknown_server_side");
            }
            Session session = store.findSession(record.getFamilyId());
            if (session == null) {
                return untrusted(declaredCallerId, "family_session_absent");
            }
            confirmedCaller = session.getCallerId();
            familyId = record.getFamilyId();
            tokenState = record.getState().name();
        }

        if (declaredCallerId == null || declaredCallerId.isBlank()) {
            // A valid credential but no declared header: identity is proven,
            // yet the API contract requires the header. Bill nobody and reject.
            return untrusted(declaredCallerId, kind + "_credential_present_but_header_absent");
        }
        if (!confirmedCaller.equals(declaredCallerId)) {
            // The header claims someone other than the credential owner:
            // forgery. Never bill the victim owner, never bill the forger as
            // the victim.
            return untrusted(declaredCallerId, "declared_caller_differs_from_credential_owner"
                    + "_owner=" + confirmedCaller + " tokenState=" + tokenState);
        }
        return new CallerIdentity(true, declaredCallerId, confirmedCaller,
                RateLimitKey.authenticated(confirmedCaller), familyId,
                "credential_owner_confirmed tokenState=" + tokenState);
    }

    /**
     * Resolve identity for the credential-less issuance endpoint. The request
     * cannot prove anything, so it is billed to an isolated ISSUANCE bucket
     * keyed by the raw declared header, which can never consume a real
     * caller's AUTHENTICATED quota.
     */
    public CallerIdentity resolveIssuanceRequest(String declaredCallerId) {
        if (declaredCallerId == null || declaredCallerId.isBlank()) {
            return untrusted(declaredCallerId, "header_X_Caller_Id_absent");
        }
        return new CallerIdentity(true, declaredCallerId, declaredCallerId,
                RateLimitKey.issuance(declaredCallerId), null,
                "issuance_namespace_isolated_from_authenticated_owners");
    }

    private CallerIdentity untrusted(String declaredCallerId, String basis) {
        return new CallerIdentity(false, declaredCallerId, null, null, null, basis);
    }

    /** Extract a Bearer token from an Authorization header value. */
    public static String bearerToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring("Bearer ".length());
        }
        return null;
    }

    /** Best-effort extraction of {@code refreshToken} from a buffered JSON body. */
    public static String refreshTokenFromJson(String jsonBody) {
        if (jsonBody == null || jsonBody.isBlank()) {
            return null;
        }
        String token = null;
        try {
            com.fasterxml.jackson.databind.JsonNode node =
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(jsonBody);
            com.fasterxml.jackson.databind.JsonNode value = node.get("refreshToken");
            if (value != null && !value.isNull()) {
                token = value.asText();
            }
        } catch (Exception ignored) {
            // Malformed JSON: no credential can be proven; the controller
            // reports the parse failure in its own shape.
            token = null;
        }
        return token;
    }
}
