package io.github.probityai.keycloak.evidence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DsseSignerTest {

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]*)\"").matcher(json);
        assertTrue(m.find(), name);
        return m.group(1);
    }

    private static boolean verifies(PublicKey key, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    @Test
    void paeMatchesTheDsseSpecificationExample() {
        byte[] expected = "DSSEv1 29 http://example.com/HelloWorld 11 hello world".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected, DsseSigner.pae("http://example.com/HelloWorld",
                "hello world".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void envelopeSignatureVerifiesOverThePreAuthenticationEncoding() throws Exception {
        KeyPair pair = Keys.ed25519();
        DsseSigner signer = new DsseSigner(pair.getPrivate(), pair.getPublic());
        byte[] payload = "{\"a\":1}".getBytes(StandardCharsets.US_ASCII);
        String envelope = signer.envelope(payload);
        assertArrayEquals(payload, Base64.getDecoder().decode(field(envelope, "payload")));
        assertEquals(DsseSigner.IN_TOTO_PAYLOAD_TYPE, field(envelope, "payloadType"));
        assertEquals(signer.keyId(), field(envelope, "keyid"));
        byte[] sig = Base64.getDecoder().decode(field(envelope, "sig"));
        assertTrue(verifies(pair.getPublic(), DsseSigner.pae(DsseSigner.IN_TOTO_PAYLOAD_TYPE, payload), sig));
        byte[] tampered = "{\"a\":2}".getBytes(StandardCharsets.US_ASCII);
        assertFalse(verifies(pair.getPublic(), DsseSigner.pae(DsseSigner.IN_TOTO_PAYLOAD_TYPE, tampered), sig));
    }

    @Test
    void keyIdIsTheSha256OfTheRawPublicKey() throws Exception {
        DsseSigner signer = Keys.signer();
        assertEquals(32, signer.rawPublicKey().length);
        assertEquals(Digests.sha256Hex(signer.rawPublicKey()), signer.keyId());
    }

    @Test
    void refusesAMismatchedKeyPair() throws Exception {
        KeyPair one = Keys.ed25519();
        KeyPair two = Keys.ed25519();
        assertThrows(GeneralSecurityException.class, () -> new DsseSigner(one.getPrivate(), two.getPublic()));
    }

    @Test
    void readsPemFiles(@TempDir Path dir) throws Exception {
        KeyPair pair = Keys.ed25519();
        Base64.Encoder mime = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
        Path priv = dir.resolve("key.pem");
        Path pub = dir.resolve("key.pub.pem");
        Files.writeString(priv, "-----BEGIN PRIVATE KEY-----\n" + mime.encodeToString(pair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
        Files.writeString(pub, "-----BEGIN PUBLIC KEY-----\n" + mime.encodeToString(pair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");
        DsseSigner signer = DsseSigner.fromPemFiles(priv, pub);
        assertEquals(new DsseSigner(pair.getPrivate(), pair.getPublic()).keyId(), signer.keyId());
        Files.writeString(pub, "not a key\n");
        assertThrows(java.io.IOException.class, () -> DsseSigner.fromPemFiles(priv, pub));
    }
}
