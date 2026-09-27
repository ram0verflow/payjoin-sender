package org.payjoin.sender;

/** The fixed reply key the fuzz targets must not print. */
public final class FuzzKeys {
    private FuzzKeys() {}

    public static byte[] reply() {
        return secret(9);
    }

    public static byte[] secret(int tag) {
        byte[] value = new byte[32];
        value[31] = (byte) tag;
        return value;
    }
}
