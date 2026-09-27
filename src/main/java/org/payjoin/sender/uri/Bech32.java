package org.payjoin.sender.uri;

/**
 * Bech32 character-set codec with no checksum. Data characters are
 * uppercase, matching BIP 77 fragment parameters and short ids.
 */
final class Bech32 {
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private Bech32() {}

    static String encode(String hrp, byte[] data) {
        if (hrp == null || hrp.isEmpty() || hrp.indexOf('1') >= 0) {
            throw new IllegalArgumentException("invalid HRP");
        }
        StringBuilder out = new StringBuilder(hrp.length() + 1 + (data.length * 8 + 4) / 5);
        out.append(hrp).append('1');
        int accumulator = 0;
        int bits = 0;
        for (byte value : data) {
            accumulator = (accumulator << 8) | (value & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(CHARSET.charAt((accumulator >> bits) & 31));
            }
        }
        if (bits > 0) {
            out.append(CHARSET.charAt((accumulator << (5 - bits)) & 31));
        }
        return out.toString().toUpperCase(java.util.Locale.ROOT);
    }

    static Decoded decode(String encoded) {
        if (encoded == null) {
            throw new UriParseException(UriParseException.Reason.INVALID_BECH32, "missing bech32");
        }
        int separator = encoded.lastIndexOf('1');
        if (separator <= 0 || separator == encoded.length() - 1) {
            throw new UriParseException(UriParseException.Reason.INVALID_BECH32, "invalid bech32");
        }
        String hrp = encoded.substring(0, separator);
        String dataPart = encoded.substring(separator + 1);
        int accumulator = 0;
        int bits = 0;
        byte[] out = new byte[dataPart.length() * 5 / 8];
        int written = 0;
        for (int i = 0; i < dataPart.length(); i++) {
            int value = CHARSET.indexOf(Character.toLowerCase(dataPart.charAt(i)));
            if (value < 0 || Character.isLowerCase(dataPart.charAt(i))) {
                throw new UriParseException(UriParseException.Reason.INVALID_BECH32, "invalid bech32");
            }
            accumulator = (accumulator << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[written++] = (byte) ((accumulator >> bits) & 0xff);
            }
        }
        if (written != out.length) {
            throw new UriParseException(UriParseException.Reason.INVALID_BECH32, "invalid bech32");
        }
        return new Decoded(hrp, out);
    }

    record Decoded(String hrp, byte[] data) {}
}
