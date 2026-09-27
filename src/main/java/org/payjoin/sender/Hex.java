package org.payjoin.sender;

final class Hex {
    private Hex() {}

    static String encode(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(Character.forDigit((value >> 4) & 0xf, 16));
            out.append(Character.forDigit(value & 0xf, 16));
        }
        return out.toString();
    }

    static byte[] decode(String hex, int expected) {
        if (hex.length() != expected * 2) {
            throw new IllegalArgumentException("session key has the wrong length");
        }
        byte[] out = new byte[expected];
        for (int i = 0; i < expected; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("session key is not hex");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
