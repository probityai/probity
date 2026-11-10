package io.github.probityai.keycloak.evidence;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Appends envelope lines to one JSONL file and keeps the hash chain that links them.
 *
 * <p>Each receipt names its stream, its index and the SHA-256 of the previous line's bytes, so a
 * removed, reordered or edited line breaks the chain a reader recomputes. The sink resumes the
 * chain from the file's last line after a restart. Each write is flushed to disk before
 * {@link #append} returns. One sink object serves one file; give each Keycloak node its own file
 * and stream name.
 */
final class ChainedSink {

    private static final Pattern CHAIN_INDEX = Pattern.compile("\"chain\":\\{\"index\":(\\d+),");

    private final Path file;
    private final String stream;
    private long nextIndex;
    private String previous;

    ChainedSink(Path file, String stream) throws IOException {
        this.file = file;
        this.stream = stream;
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        resume();
    }

    private void resume() throws IOException {
        if (!Files.exists(file)) {
            nextIndex = 0;
            previous = null;
            return;
        }
        List<String> lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
        String last = null;
        for (int i = lines.size() - 1; i >= 0 && last == null; i--) {
            if (!lines.get(i).isBlank()) {
                last = lines.get(i);
            }
        }
        if (last == null) {
            nextIndex = 0;
            previous = null;
            return;
        }
        nextIndex = lastIndex(last) + 1;
        previous = Digests.sha256Hex(last.getBytes(StandardCharsets.US_ASCII));
    }

    private static long lastIndex(String line) throws IOException {
        Matcher payload = Pattern.compile("\"payload\":\"([A-Za-z0-9+/=]+)\"").matcher(line);
        if (!payload.find()) {
            throw new IOException("the last line of the evidence sink is not an envelope");
        }
        String statement = new String(Base64.getDecoder().decode(payload.group(1)), StandardCharsets.UTF_8);
        Matcher index = CHAIN_INDEX.matcher(statement);
        if (!index.find()) {
            throw new IOException("the last envelope of the evidence sink carries no chain index");
        }
        return Long.parseLong(index.group(1));
    }

    /**
     * Writes one receipt. {@code render} receives the chain position and returns the envelope line.
     *
     * @return the line written, without its newline
     */
    synchronized String append(Function<GrantRecord.Chain, String> render) throws IOException {
        String line = render.apply(new GrantRecord.Chain(stream, nextIndex, previous));
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.US_ASCII);
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        previous = Digests.sha256Hex(line.getBytes(StandardCharsets.US_ASCII));
        nextIndex++;
        return line;
    }
}
