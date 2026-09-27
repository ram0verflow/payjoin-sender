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
            throw new CounterpartyException(
                    "receiver rejected the original: " + new String(plaintext, 0, shown, java.nio.charset.StandardCharsets.US_ASCII));
        }
        int end = end(plaintext);
        for (int i = end; i < plaintext.length; i++) {
            if (plaintext[i] != 0) {
                throw new CounterpartyException("proposal padding is not zero");
            }
        }
        return java.util.Arrays.copyOf(plaintext, end);
    }
}
