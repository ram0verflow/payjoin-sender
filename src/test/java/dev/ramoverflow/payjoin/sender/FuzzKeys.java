package dev.ramoverflow.payjoin.sender;

/** Test-only keys. The fuzz targets must not print the reply key. */
public final class FuzzKeys {
    private FuzzKeys() {}

    /** Test-only reply secret. Not a wallet key. */
    public static byte[] reply() {
        return secret(9);
    }

    /** Test-only 32-byte scalar. {@code tag} is the last byte. */
    public static byte[] secret(int tag) {
        byte[] value = new byte[32];
        value[31] = (byte) tag;
        return value;
    }
}
