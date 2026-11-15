package io.github.probityai.keycloak.evidence;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * The {@code evidence-hook} event listener.
 *
 * <p>Options, set as {@code --spi-events-listener--evidence-hook--<option>=<value>}:
 * <ul>
 *   <li>{@code signing-key-file}: PKCS#8 PEM of the Ed25519 private key (required)</li>
 *   <li>{@code public-key-file}: PEM of the matching public key (required)</li>
 *   <li>{@code sink-file}: the JSONL file receipts are appended to (required)</li>
 *   <li>{@code stream}: the chain's stream name, one per node (default: the host name)</li>
 *   <li>{@code event-types}: comma-separated event types to record (default: all three grants)</li>
 * </ul>
 * A missing or unreadable key, or a key pair that does not match, stops Keycloak at start, so a
 * realm never runs believing it records grants while it cannot sign them.
 */
public final class EvidenceHookProviderFactory implements EventListenerProviderFactory {

    public static final String ID = "evidence-hook";
    private static final Logger LOG = Logger.getLogger(EvidenceHookProviderFactory.class);

    record Settings(DsseSigner signer, ChainedSink sink, Set<String> eventTypes, AtomicLong failures) {
    }

    private Settings settings;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new EvidenceHookProvider(session, settings);
    }

    @Override
    public void init(Config.Scope config) {
        String privateKey = required(config, "signing-key-file");
        String publicKey = required(config, "public-key-file");
        String sinkFile = required(config, "sink-file");
        String stream = config.get("stream", hostName());
        Set<String> types = new LinkedHashSet<>(Arrays.asList(
                config.get("event-types", String.join(",", GrantRecord.GRANT_TYPES.keySet())).split(",")));
        types.removeIf(String::isBlank);
        for (String type : types) {
            if (!GrantRecord.recorded(type)) {
                throw new IllegalStateException(ID + ": event type " + type + " is not a recorded grant");
            }
        }
        try {
            DsseSigner signer = DsseSigner.fromPemFiles(Path.of(privateKey), Path.of(publicKey));
            ChainedSink sink = new ChainedSink(Path.of(sinkFile), stream);
            settings = new Settings(signer, sink, Set.copyOf(types), new AtomicLong());
            LOG.infof("%s: recording %s to %s as stream %s under key %s", ID, types, sinkFile, stream,
                    signer.keyId());
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(ID + ": cannot start: " + e.getMessage(), e);
        }
    }

    private static String required(Config.Scope config, String name) {
        String value = config.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(ID + ": option " + name + " is required");
        }
        return value;
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "keycloak";
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to wire after start.
    }

    @Override
    public void close() {
        if (settings != null && settings.failures().get() > 0) {
            LOG.errorf("%s: %d receipts were not written", ID, settings.failures().get());
        }
    }

    @Override
    public String getId() {
        return ID;
    }
}
