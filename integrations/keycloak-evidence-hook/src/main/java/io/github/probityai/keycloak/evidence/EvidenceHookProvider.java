package io.github.probityai.keycloak.evidence;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;

/**
 * Writes one signed receipt for each successful token exchange, client credentials grant and CIBA
 * token grant in a realm that lists this listener.
 *
 * <p>Keycloak calls the listener in the request thread, after the token response is built. The
 * subject and actor tokens are read from the request form and hashed at once; the issued token is
 * named by the SHA-256 of its {@code jti}. A failed write is logged at ERROR with the event id and
 * counted; it does not change the token response.
 */
final class EvidenceHookProvider implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(EvidenceHookProvider.class);

    private final KeycloakSession session;
    private final EvidenceHookProviderFactory.Settings settings;

    EvidenceHookProvider(KeycloakSession session, EvidenceHookProviderFactory.Settings settings) {
        this.session = session;
        this.settings = settings;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() == null || !settings.eventTypes().contains(event.getType().name())
                || event.getError() != null) {
            return;
        }
        try {
            GrantRecord.Input input = input(event);
            settings.sink().append(chain -> render(input, chain));
        } catch (IOException | RuntimeException e) {
            settings.failures().incrementAndGet();
            LOG.errorf(e, "evidence receipt not written for event %s", event.getId());
        }
    }

    private String render(GrantRecord.Input input, GrantRecord.Chain chain) {
        Map<String, Object> statement = GrantRecord.statement(input, chain, settings.signer().keyId());
        byte[] payload = CanonicalJson.write(statement).getBytes(StandardCharsets.US_ASCII);
        try {
            return settings.signer().envelope(payload);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    private GrantRecord.Input input(Event event) {
        KeycloakContext context = session.getContext();
        String subjectToken = null;
        String actorToken = null;
        HttpRequest request = context.getHttpRequest();
        if (request != null) {
            MultivaluedMap<String, String> form = request.getDecodedFormParameters();
            subjectToken = Digests.sha256OfText(form.getFirst("subject_token"));
            actorToken = Digests.sha256OfText(form.getFirst("actor_token"));
        }
        return new GrantRecord.Input(event.getType().name(), event.getId(), event.getTime(),
                issuer(context, event.getRealmName()), event.getClientId(), event.getUserId(),
                event.getDetails(), subjectToken, actorToken);
    }

    private static String issuer(KeycloakContext context, String realmName) {
        URI base = context.getUri().getBaseUri();
        String text = base.toString();
        return (text.endsWith("/") ? text : text + "/") + "realms/" + realmName;
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin events change configuration; they issue no token and get no receipt.
    }

    @Override
    public void close() {
        // The sink and signer belong to the factory and outlive this provider.
    }
}
