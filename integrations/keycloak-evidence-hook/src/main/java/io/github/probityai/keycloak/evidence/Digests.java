package io.github.probityai.keycloak.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 helpers. A token value is hashed the moment it is read and never kept. */
final class Digests {

    private Digests() {
    }

    static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    /** The SHA-256 of a text's UTF-8 bytes, or null for a null or empty text. */
    static String sha256OfText(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }
}
