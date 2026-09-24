package org.payjoin.sender.uri;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/** Eight-byte mailbox id, written as uppercase bech32 data with no HRP and no checksum. */
public final class ShortId {
    private final byte[] bytes;

    private ShortId(byte[] bytes) {
        this.bytes = bytes;
    }

    public static ShortId parse(String encoded) {
        Bech32.Decoded decoded = Bech32.decode("ID1" + encoded);
        if (!decoded.hrp().equals("ID") || decoded.data().length != 8) {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "invalid short id");
        }
        return new ShortId(decoded.data());
    }

    public static ShortId fromCompressedKey(byte[] compressedKey) {
        if (compressedKey == null || compressedKey.length != 33) {
            throw new IllegalArgumentException("compressed key must be 33 bytes");
        }
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(compressedKey);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return new ShortId(Arrays.copyOf(digest, 8));
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    @Override
    public String toString() {
        String encoded = Bech32.encode("ID", bytes);
        return encoded.substring(3);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ShortId that && Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
