package io.github.probityai.keycloak.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class GrantRecordTest {

    private static final String SUBJECT_TOKEN = "eyJhbGciOiJSUzI1NiJ9.subject.signature";

    private static Map<String, String> exchangeDetails() {
        Map<String, String> details = new HashMap<>();
        details.put("token_id", "onrtte:5f1c");
        details.put("audience", "tools-api  agent-gateway");
        details.put("scope", "tools:write profile tools:read");
        details.put("subject_token_client_id", "agent-ui");
        details.put("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        details.put("client_auth_method", "client-secret");
        return details;
    }

    private static GrantRecord.Input exchange(Map<String, String> details) {
        return new GrantRecord.Input("TOKEN_EXCHANGE", "ev-1", 1794290000123L,
                "http://127.0.0.1:8080/realms/agents", "agent-gateway", "user-1", details,
                Digests.sha256OfText(SUBJECT_TOKEN), null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> predicate(Map<String, Object> statement) {
        return (Map<String, Object>) statement.get("predicate");
    }

    @Test
    void tokenExchangeStatementCarriesDigestsAndSortedLists() {
        Map<String, Object> statement = GrantRecord.statement(exchange(exchangeDetails()),
                new GrantRecord.Chain("node-a", 0, null), "k".repeat(64));
        assertEquals(GrantRecord.PREDICATE_TYPE, statement.get("predicateType"));
        Map<String, Object> predicate = predicate(statement);
        assertEquals("urn:ietf:params:oauth:grant-type:token-exchange", predicate.get("grantType"));
        assertEquals("2026-11-10T05:53:20Z", predicate.get("issuedAt"));
        assertEquals(List.of("agent-gateway", "tools-api"), predicate.get("audience"));
        assertEquals(List.of("profile", "tools:read", "tools:write"), predicate.get("scope"));
        assertEquals(Map.of("sha256", Digests.sha256OfText(SUBJECT_TOKEN), "issuedTo", "agent-ui"),
                predicate.get("subjectToken"));
        assertEquals(List.of(Map.of("name", "access-token-id",
                "digest", Map.of("sha256", Digests.sha256OfText("onrtte:5f1c")))), statement.get("subject"));
        String json = CanonicalJson.write(statement);
        assertFalse(json.contains(SUBJECT_TOKEN), "a token value must never reach the receipt");
        assertFalse(json.contains("onrtte:5f1c"), "the token id appears only as a digest");
    }

    @Test
    void clientCredentialsGrantHasNoSubjectToken() {
        Map<String, String> details = new HashMap<>();
        details.put("token_id", "trrtcc:1");
        GrantRecord.Input input = new GrantRecord.Input("CLIENT_LOGIN", "ev-2", 0L, "https://idp/realms/r",
                "svc", "svc-user", details, null, null);
        Map<String, Object> predicate = predicate(GrantRecord.statement(input,
                new GrantRecord.Chain("s", 4, "a".repeat(64)), "k"));
        assertEquals("client_credentials", predicate.get("grantType"));
        assertNull(predicate.get("subjectToken"));
        assertEquals(List.of(), predicate.get("scope"));
        assertEquals(Map.of("stream", "s", "index", 4L, "previous", "a".repeat(64)), predicate.get("chain"));
    }

    @Test
    void cibaGrantIsNamedByItsGrantTypeUrn() {
        Map<String, String> details = new HashMap<>();
        details.put("token_id", "x");
        GrantRecord.Input input = new GrantRecord.Input("AUTHREQID_TO_TOKEN", "ev-3", 0L, "i", "c", "u",
                details, null, null);
        assertEquals("urn:openid:params:grant-type:ciba",
                predicate(GrantRecord.statement(input, new GrantRecord.Chain("s", 0, null), "k")).get("grantType"));
    }

    @Test
    void refusesAnEventWithoutAnIssuedToken() {
        Map<String, String> details = exchangeDetails();
        details.remove("token_id");
        assertThrows(IllegalArgumentException.class, () -> GrantRecord.statement(exchange(details),
                new GrantRecord.Chain("s", 0, null), "k"));
    }

    @Test
    void refusesAnEventTypeThatIsNotAGrant() {
        GrantRecord.Input input = new GrantRecord.Input("LOGIN", "e", 0L, "i", "c", "u", exchangeDetails(),
                null, null);
        assertFalse(GrantRecord.recorded("LOGIN"));
        assertThrows(IllegalArgumentException.class, () -> GrantRecord.statement(input,
                new GrantRecord.Chain("s", 0, null), "k"));
    }
}
