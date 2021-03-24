package io.casperlabs.hashtest;

import java.util.Arrays;

import ove.crypto.digest.Blake2b;

public class App {
    public static final String ED25519_LOWERCASE = "ed25519";
    public static final String SECP256K1_LOWERCASE = "secp256k1";

    public static byte[] makeAccountHash(String algorithm, byte[] pubKeyBytes) throws RuntimeException {
        switch (algorithm) {
        case ED25519_LOWERCASE:
            if (pubKeyBytes.length != 32) {
                throw new RuntimeException("Ed25519 public key should have 32 bytes");
            }
            break;
        case SECP256K1_LOWERCASE:
            if (pubKeyBytes.length != 33) {
                // NOTE: This requires secp256k1 public key bytes in compressed form which
                // consists of 33 bytes.
                throw new RuntimeException("Secp256k1 public key should have 33 bytes");
            }
            break;
        default:
            throw new RuntimeException("Invalid public key variant");
        }

        final Blake2b blake2b = Blake2b.Digest.newInstance(32);

        blake2b.update(algorithm.getBytes());
        blake2b.update((byte) 0);
        blake2b.update(pubKeyBytes);

        return blake2b.digest();
    }

    public static void main(String[] args) {
    }
}
