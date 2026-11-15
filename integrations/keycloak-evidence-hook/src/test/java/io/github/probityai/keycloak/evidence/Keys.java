package io.github.probityai.keycloak.evidence;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

final class Keys {

    private Keys() {
    }

    static KeyPair ed25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    static DsseSigner signer() throws GeneralSecurityException {
        KeyPair pair = ed25519();
        return new DsseSigner(pair.getPrivate(), pair.getPublic());
    }
}
