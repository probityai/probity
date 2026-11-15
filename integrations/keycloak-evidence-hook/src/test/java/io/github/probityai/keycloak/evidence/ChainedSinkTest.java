package io.github.probityai.keycloak.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ChainedSinkTest {

    private static String write(ChainedSink sink, DsseSigner signer, List<GrantRecord.Chain> seen) throws IOException {
        Map<String, String> details = new HashMap<>();
        details.put("token_id", "t" + seen.size());
        GrantRecord.Input input = new GrantRecord.Input("CLIENT_LOGIN", "e" + seen.size(), 0L, "i", "c", "u",
                details, null, null);
        return sink.append(chain -> {
            seen.add(chain);
            try {
                return signer.envelope(CanonicalJson.write(GrantRecord.statement(input, chain, signer.keyId()))
                        .getBytes(StandardCharsets.US_ASCII));
            } catch (GeneralSecurityException e) {
                throw new UncheckedIOException(new IOException(e));
            }
        });
    }

    @Test
    void linksEachLineToThePreviousAndResumesAfterRestart(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("sink/receipts.jsonl");
        DsseSigner signer = Keys.signer();
        List<GrantRecord.Chain> seen = new ArrayList<>();
        ChainedSink sink = new ChainedSink(file, "node-a");
        String first = write(sink, signer, seen);
        String second = write(sink, signer, seen);
        assertNull(seen.get(0).previous());
        assertEquals(0, seen.get(0).index());
        assertEquals(Digests.sha256Hex(first.getBytes(StandardCharsets.US_ASCII)), seen.get(1).previous());

        ChainedSink resumed = new ChainedSink(file, "node-a");
        write(resumed, signer, seen);
        assertEquals(2, seen.get(2).index());
        assertEquals(Digests.sha256Hex(second.getBytes(StandardCharsets.US_ASCII)), seen.get(2).previous());
        assertEquals(3, Files.readAllLines(file).size());
    }

    @Test
    void refusesToResumeFromALineThatIsNotAnEnvelope(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("receipts.jsonl");
        Files.writeString(file, "{\"not\":\"an envelope\"}\n");
        assertThrows(IOException.class, () -> new ChainedSink(file, "s"));
    }
}
