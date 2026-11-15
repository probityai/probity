package io.github.probityai.keycloak.evidence;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Builds the in-toto Statement for one successful token grant.
 *
 * <p>The inputs carry no token value: the caller hashes the subject and actor tokens before
 * building, and the issued token appears only as the SHA-256 of its {@code jti}. The class has no
 * Keycloak dependency, so every rule here is tested without a server.
 */
final class GrantRecord {

    static final String STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
    static final String PREDICATE_TYPE = "https://w3id.org/agent-evidence/predicate/v1/token-grant-receipt";
    static final String RECORDER_ID = "keycloak-evidence-hook";
    static final String RECORDER_VERSION = "0.1.0";

    /** The grant types a receipt can name, keyed by the Keycloak event type that reports them. */
    static final Map<String, String> GRANT_TYPES = Map.of(
            "TOKEN_EXCHANGE", "urn:ietf:params:oauth:grant-type:token-exchange",
            "CLIENT_LOGIN", "client_credentials",
            "AUTHREQID_TO_TOKEN", "urn:openid:params:grant-type:ciba");

    /**
     * What one grant event established, with every token already reduced to a digest.
     *
     * @param eventType the Keycloak event type name, one of {@link #GRANT_TYPES}
     * @param eventId the Keycloak event id
     * @param timeMillis the event time in milliseconds since the epoch
     * @param issuer the realm issuer URL
     * @param clientId the client that made the token request (the actor)
     * @param userId the Keycloak user id the issued token names
     * @param details the event details Keycloak recorded
     * @param subjectTokenSha256 SHA-256 of the presented subject_token, or null
     * @param actorTokenSha256 SHA-256 of the presented actor_token, or null
     */
    record Input(String eventType, String eventId, long timeMillis, String issuer, String clientId,
                 String userId, Map<String, String> details, String subjectTokenSha256,
                 String actorTokenSha256) {
    }

    /** Where the receipt sits in its sink's hash chain. */
    record Chain(String stream, long index, String previous) {
    }

    private GrantRecord() {
    }

    static boolean recorded(String eventType) {
        return GRANT_TYPES.containsKey(eventType);
    }

    /**
     * The statement as a map ready for {@link CanonicalJson}.
     *
     * @throws IllegalArgumentException when the event does not name an issued access token, a
     *     client or a user; such an event is not a completed grant and gets no receipt.
     */
    static Map<String, Object> statement(Input in, Chain chain, String keyId) {
        String grantType = GRANT_TYPES.get(in.eventType());
        if (grantType == null) {
            throw new IllegalArgumentException("not a recorded grant event: " + in.eventType());
        }
        Map<String, String> details = in.details() == null ? Map.of() : in.details();
        String tokenId = details.get("token_id");
        if (blank(tokenId) || blank(in.clientId()) || blank(in.userId()) || blank(in.eventId())) {
            throw new IllegalArgumentException("the event names no issued token, client, user or id");
        }
        Map<String, Object> actor = new LinkedHashMap<>();
        actor.put("clientId", in.clientId());
        actor.put("authMethod", emptyToNull(details.get("client_auth_method")));

        Map<String, Object> subjectToken = null;
        if (in.subjectTokenSha256() != null) {
            subjectToken = new LinkedHashMap<>();
            subjectToken.put("sha256", in.subjectTokenSha256());
            subjectToken.put("issuedTo", emptyToNull(details.get("subject_token_client_id")));
        }

        Map<String, Object> chainMap = new LinkedHashMap<>();
        chainMap.put("stream", chain.stream());
        chainMap.put("index", chain.index());
        chainMap.put("previous", chain.previous());

        Map<String, Object> predicate = new LinkedHashMap<>();
        predicate.put("issuer", in.issuer());
        predicate.put("grantType", grantType);
        predicate.put("eventId", in.eventId());
        predicate.put("issuedAt", instant(in.timeMillis()));
        predicate.put("actor", actor);
        predicate.put("subject", Map.of("userId", in.userId()));
        predicate.put("subjectToken", subjectToken);
        predicate.put("actorTokenSha256", in.actorTokenSha256());
        predicate.put("requestedTokenType", emptyToNull(details.get("requested_token_type")));
        predicate.put("audience", words(details.get("audience")));
        predicate.put("scope", words(details.get("scope")));
        predicate.put("refreshTokenIdSha256", Digests.sha256OfText(details.get("refresh_token_id")));
        predicate.put("recorder", Map.of("id", RECORDER_ID, "version", RECORDER_VERSION, "keyId", keyId));
        predicate.put("chain", chainMap);

        Map<String, Object> subject = Map.of(
                "name", "access-token-id",
                "digest", Map.of("sha256", Digests.sha256OfText(tokenId)));
        Map<String, Object> statement = new LinkedHashMap<>();
        statement.put("_type", STATEMENT_TYPE);
        statement.put("subject", List.of(subject));
        statement.put("predicateType", PREDICATE_TYPE);
        statement.put("predicate", predicate);
        return statement;
    }

    /** RFC 3339 UTC to whole seconds. */
    static String instant(long timeMillis) {
        return DateTimeFormatter.ISO_INSTANT.format(
                Instant.ofEpochMilli(timeMillis).truncatedTo(ChronoUnit.SECONDS));
    }

    /** A space-separated list as a sorted, duplicate-free list; an absent value is empty. */
    static List<String> words(String text) {
        if (blank(text)) {
            return Collections.emptyList();
        }
        TreeSet<String> sorted = new TreeSet<>(Arrays.asList(text.trim().split("\\s+")));
        return new ArrayList<>(sorted);
    }

    private static String emptyToNull(String text) {
        return blank(text) ? null : text;
    }

    private static boolean blank(String text) {
        return text == null || text.isBlank();
    }
}
