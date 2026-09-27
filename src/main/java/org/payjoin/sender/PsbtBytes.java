package org.payjoin.sender;

/** Version-0 PSBT boundaries. Padding after the maps must be zero. */
final class PsbtBytes {
    private PsbtBytes() {}

    static int end(byte[] data) {
        return Psbt.read(data).end;
    }

    static byte[] proposal(byte[] plaintext) {
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("empty proposal");
        }
        if (plaintext[0] == '{') {
            int end = 0;
            while (end < plaintext.length && plaintext[end] != 0) {
                end++;
            }
            int shown = Math.min(end, 200);
            throw new CounterpartyException("receiver rejected the original: " + printable(plaintext, shown));
        }
        int end = end(plaintext);
        for (int i = end; i < plaintext.length; i++) {
            if (plaintext[i] != 0) {
                throw new CounterpartyException("proposal padding is not zero");
            }
        }
        return java.util.Arrays.copyOf(plaintext, end);
    }

    /** Printable ASCII only. Other bytes are dropped, not replaced. */
    private static String printable(byte[] data, int length) {
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int value = data[i] & 0xff;
            if (value >= 0x20 && value <= 0x7e) {
                out.append((char) value);
            }
        }
        return out.toString();
    }
}
