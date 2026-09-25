package org.payjoin.sender.ohttp;

import org.payjoin.sender.crypto.Secp256k1;

/**
 * The 34-byte OHTTP key from a BIP 77 fragment: one key-id byte and a
 * compressed secp256k1 key. The RFC 9458 key config is rebuilt from that.
 */
public final class OhttpKeys {
    private static final byte[] KEM = new byte[] {0x00, 0x16};
    private static final byte[] SYMMETRIC = new byte[] {0x00, 0x04, 0x00, 0x01, 0x00, 0x03};

    private final byte keyId;
    private final byte[] uncompressed;

    private OhttpKeys(byte keyId, byte[] uncompressed) {
        this.keyId = keyId;
        this.uncompressed = uncompressed;
    }

    public static OhttpKeys parse(byte[] encoded) {
        if (encoded.length != 34) {
            throw new IllegalArgumentException("OHTTP key must be 34 bytes");
        }
        int prefix = encoded[1] & 0xff;
        if (prefix != 0x02 && prefix != 0x03) {
            throw new IllegalArgumentException("OHTTP key must be compressed");
        }
        byte[] compressed = java.util.Arrays.copyOfRange(encoded, 1, 34);
        return new OhttpKeys(encoded[0], Secp256k1.uncompressed(compressed));
    }

    byte keyId() {
        return keyId;
    }

    byte[] publicKey() {
        return uncompressed.clone();
    }

    /** key id || KEM 0x0016 || uncompressed key || symmetric length || KDF 0x0001 AEAD 0x0003. */
    public byte[] keyConfig() {
        byte[] config = new byte[1 + KEM.length + uncompressed.length + SYMMETRIC.length];
        config[0] = keyId;
        System.arraycopy(KEM, 0, config, 1, KEM.length);
        System.arraycopy(uncompressed, 0, config, 3, uncompressed.length);
        System.arraycopy(SYMMETRIC, 0, config, 68, SYMMETRIC.length);
        return config;
    }
}
