package org.payjoin.sender;

/** Enough of a version-0 PSBT to find where the maps end and the zero padding begins. */
final class PsbtBytes {
    private PsbtBytes() {}

    static int end(byte[] data) {
        Cursor cursor = new Cursor(data);
        if (cursor.u8() != 'p' || cursor.u8() != 's' || cursor.u8() != 'b' || cursor.u8() != 't' || cursor.u8() != 0xff) {
            throw new IllegalArgumentException("not a psbt");
        }
        byte[] unsigned = null;
        while (true) {
            int keyLength = cursor.compact();
            if (keyLength == 0) {
                break;
            }
            int type = cursor.u8();
            cursor.skip(keyLength - 1);
            int valueLength = cursor.compact();
            if (type == 0x00 && keyLength == 1) {
                if (unsigned != null) {
                    throw new IllegalArgumentException("psbt has two unsigned transactions");
                }
                unsigned = cursor.take(valueLength);
            } else {
                cursor.skip(valueLength);
            }
        }
        if (unsigned == null) {
            throw new IllegalArgumentException("psbt has no unsigned transaction");
        }
        int[] counts = counts(unsigned);
        for (int i = 0; i < counts[0] + counts[1]; i++) {
            skipMap(cursor);
        }
        return cursor.i;
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

    private static int[] counts(byte[] transaction) {
        Cursor cursor = new Cursor(transaction);
        cursor.skip(4);
        int inputs = cursor.compact();
        if (inputs <= 0) {
            throw new IllegalArgumentException("psbt transaction is not the unsigned form");
        }
        for (int i = 0; i < inputs; i++) {
            cursor.skip(36);
            cursor.skip(cursor.compact());
            cursor.skip(4);
        }
        int outputs = cursor.compact();
        for (int i = 0; i < outputs; i++) {
            cursor.skip(8);
            cursor.skip(cursor.compact());
        }
        cursor.skip(4);
        if (cursor.i != transaction.length) {
            throw new IllegalArgumentException("psbt transaction has trailing bytes");
        }
        return new int[] {inputs, outputs};
    }

    private static void skipMap(Cursor cursor) {
        while (true) {
            int keyLength = cursor.compact();
            if (keyLength == 0) {
                return;
            }
            cursor.skip(keyLength);
            cursor.skip(cursor.compact());
        }
    }

    private static final class Cursor {
        private final byte[] data;
        private int i;

        private Cursor(byte[] data) {
            this.data = data;
        }

        private int u8() {
            if (i >= data.length) {
                throw new IllegalArgumentException("truncated psbt");
            }
            return data[i++] & 0xff;
        }

        private void skip(int length) {
            if (length < 0 || i > data.length - length) {
                throw new IllegalArgumentException("truncated psbt");
            }
            i += length;
        }

        private byte[] take(int length) {
            int start = i;
            skip(length);
            return java.util.Arrays.copyOfRange(data, start, i);
        }

        private int compact() {
            int first = u8();
            long value;
            if (first < 0xfd) {
                value = first;
            } else if (first == 0xfd) {
                value = u8() | (u8() << 8);
            } else if (first == 0xfe) {
                value = u8() | ((long) u8() << 8) | ((long) u8() << 16) | ((long) u8() << 24);
            } else {
                throw new IllegalArgumentException("psbt length is too large");
            }
            if (value > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("psbt length is too large");
            }
            return (int) value;
        }
    }
}
