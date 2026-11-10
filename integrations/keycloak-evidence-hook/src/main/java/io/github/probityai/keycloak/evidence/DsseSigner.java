package io.github.probityai.keycloak.evidence;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Signs a payload as a DSSE v1 envelope with one Ed25519 key the realm operator supplies.
 *
 * <p>The operator gives a PKCS#8 private key and its SubjectPublicKeyInfo public key as PEM files.
 * The pair is checked at start: a probe message signed with the private key must verify under the
 * public key. The key id is the lowercase hex SHA-256 of the 32 raw public key bytes, the same value
 * the offline verifier reports for an accepting key.
 */
final class DsseSigner {

    static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
    private static final int ED25519_SPKI_LENGTH = 44;

    private final PrivateKey privateKey;
    private final byte[] rawPublicKey;
    private final String keyId;

    DsseSigner(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        this.privateKey = privateKey;
        byte[] spki = publicKey.getEncoded();
        if (!"Ed25519".equals(publicKey.getAlgorithm()) && !"EdDSA".equals(publicKey.getAlgorithm())
                || spki.length != ED25519_SPKI_LENGTH) {
            throw new GeneralSecurityException("the public key is not an Ed25519 key");
        }
        this.rawPublicKey = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        this.keyId = Digests.sha256Hex(rawPublicKey);
        byte[] probe = "keycloak-evidence-hook key check".getBytes(StandardCharsets.US_ASCII);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(probe);
        if (!verifier.verify(sign(probe))) {
            throw new GeneralSecurityException("the private key does not match the public key");
        }
    }

    static DsseSigner fromPemFiles(Path privatePem, Path publicPem) throws IOException, GeneralSecurityException {
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = factory.generatePrivate(
                new PKCS8EncodedKeySpec(pemBody(privatePem, "PRIVATE KEY")));
        PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(pemBody(publicPem, "PUBLIC KEY")));
        return new DsseSigner(privateKey, publicKey);
    }

    static byte[] pemBody(Path path, String label) throws IOException {
        String text = Files.readString(path, StandardCharsets.US_ASCII);
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int start = text.indexOf(begin);
        int stop = text.indexOf(end);
        if (start < 0 || stop < start) {
            throw new IOException(path + ": expected one PEM block labelled " + label);
        }
        String body = text.substring(start + begin.length(), stop).replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    String keyId() {
        return keyId;
    }

    byte[] rawPublicKey() {
        return rawPublicKey.clone();
    }

    /** The DSSE v1 pre-authentication encoding; lengths count bytes. */
    static byte[] pae(String payloadType, byte[] payload) {
        byte[] type = payloadType.getBytes(StandardCharsets.UTF_8);
        byte[] head = ("DSSEv1 " + type.length + " " + payloadType + " " + payload.length + " ")
                .getBytes(StandardCharsets.UTF_8);
        byte[] out = Arrays.copyOf(head, head.length + payload.length);
        System.arraycopy(payload, 0, out, head.length, payload.length);
        return out;
    }

    private byte[] sign(byte[] message) throws GeneralSecurityException {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    /** One envelope line: canonical JSON with the payload and the signature in padded base64. */
    String envelope(byte[] payload) throws GeneralSecurityException {
        byte[] signature = sign(pae(IN_TOTO_PAYLOAD_TYPE, payload));
        Base64.Encoder b64 = Base64.getEncoder();
        return CanonicalJson.write(Map.of(
                "payload", b64.encodeToString(payload),
                "payloadType", IN_TOTO_PAYLOAD_TYPE,
                "signatures", List.of(Map.of("keyid", keyId, "sig", b64.encodeToString(signature)))));
    }
}
