package io.casperlabs.hashtest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest {
    @Test
    public void shouldMakeAccountHashFromEd25519() {
        // Rust:
        // let secret_key = SecretKey::ed25519([42; 32]);
        // let public_key = PublicKey::from(&secret_key);
        // let truth = public_key.to_account_hash();

        byte[] ed25519Bytes = { 0x19, 0x7f, 0x6b, 0x23, (byte) 0xe1, 0x6c, (byte) 0x85, 0x32, (byte) 0xc6, (byte) 0xab,
                (byte) 0xc8, 0x38, (byte) 0xfa, (byte) 0xcd, 0x5e, (byte) 0xa7, (byte) 0x89, (byte) 0xbe, 0x0c, 0x76,
                (byte) 0xb2, (byte) 0x92, 0x03, 0x34, 0x03, (byte) 0x9b, (byte) 0xfa, (byte) 0x8b, 0x3d, 0x36,
                (byte) 0x8d, 0x61 };
        byte[] ed25519Truth = { 0x30, 0x66, 0x33, (byte) 0xf9, 0x62, 0x15, 0x5a, 0x7d, 0x46, 0x65, (byte) 0x8a,
                (byte) 0xdb, 0x36, 0x14, 0x3f, 0x28, 0x66, (byte) 0x8f, 0x53, 0x04, 0x54, (byte) 0xfe, 0x78,
                (byte) 0x8c, (byte) 0x92, 0x7c, (byte) 0xec, (byte) 0xf6, 0x2e, 0x59, 0x64, (byte) 0xa1 };
        byte[] ed25519Hash = App.makeAccountHash(App.ED25519_LOWERCASE, ed25519Bytes);

        assertArrayEquals(ed25519Truth, ed25519Hash);
    }

    @Test
    public void shouldMakeAccountHashFromSecp256k1() {
        // Rust:
        // let secret_key = SecretKey::secp256k1([42; 32]);
        // let public_key = PublicKey::from(&secret_key);
        // let truth = public_key.to_account_hash();

        byte[] secp256k1Bytes = { 0x03, 0x5b, (byte) 0xe5, (byte) 0xe9, 0x47, (byte) 0x82, 0x09, 0x67, 0x4a,
                (byte) 0x96, (byte) 0xe6, 0x0f, 0x1f, 0x03, 0x7f, 0x61, 0x76, 0x54, 0x0f, (byte) 0xd0, 0x01,
                (byte) 0xfa, 0x1d, 0x64, 0x69, 0x47, 0x70, (byte) 0xc5, 0x6a, 0x77, 0x09, (byte) 0xc4, 0x2c };
        byte[] secp256k1Truth = { 0x39, 0x19, 0x72, (byte) 0xfe, (byte) 0xa0, 0x58, 0x77, 0x51, 0x36, 0x54, 0x4e, 0x55,
                (byte) 0xc8, (byte) 0xa2, (byte) 0xad, 0x63, 0x4c, 0x6d, (byte) 0xff, (byte) 0xff, (byte) 0xf3, 0x32,
                0x4c, 0x25, (byte) 0xc4, (byte) 0xd5, 0x18, (byte) 0x87, (byte) 0xb8, 0x5e, (byte) 0x87, 0x57 };
        byte[] secp256k1Hash = App.makeAccountHash(App.SECP256K1_LOWERCASE, secp256k1Bytes);

        assertArrayEquals(secp256k1Truth, secp256k1Hash);
    }
}