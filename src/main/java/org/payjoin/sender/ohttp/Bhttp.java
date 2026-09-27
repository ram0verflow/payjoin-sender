package org.payjoin.sender.ohttp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Known-length Binary HTTP, the subset a BIP 77 sender sends and receives. */
final class Bhttp {
    private Bhttp() {}

    static byte[] request(String method, String scheme, String authority, String path, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeVarint(out, 0);
        writeVec(out, ascii(method));
        writeVec(out, ascii(scheme));
        writeVec(out, ascii(authority));
        writeVec(out, ascii(path));
        writeVec(out, new byte[0]);
        writeVec(out, body);
        writeVec(out, new byte[0]);
        return out.toByteArray();
    }

    static Reply response(byte[] encoded) {
        Cursor cursor = new Cursor(encoded);
        long framing = cursor.varint();
        if (framing != 1) {
            throw new IllegalArgumentException("OHTTP response is not a known-length Binary HTTP response");
        }
        int status = (int) cursor.varint();
        cursor.skipVec();
        byte[] body = cursor.vec();
        cursor.skipVec();
        return new Reply(status, body);
    }

    static byte[] responseBytes(int status, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeVarint(out, 1);
        writeVarint(out, status);
        writeVec(out, new byte[0]);
        writeVec(out, body);
        writeVec(out, new byte[0]);
        return out.toByteArray();
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static void writeVec(ByteArrayOutputStream out, byte[] value) {
        writeVarint(out, value.length);
        out.write(value, 0, value.length);
    }

    private static void writeVarint(ByteArrayOutputStream out, long value) {
        if (value < 1L << 6) {
            out.write((int) value);
        } else if (value < 1L << 14) {
            int encoded = (int) value | (1 << 14);
            out.write(encoded >> 8);
            out.write(encoded);
        } else if (value < 1L << 30) {
            int encoded = (int) value | (2 << 30);
            out.write(encoded >> 24);
            out.write(encoded >> 16);
            out.write(encoded >> 8);
            out.write(encoded);
        } else {
            throw new IllegalArgumentException("Binary HTTP integer is too large");
        }
    }

    record Reply(int status, byte[] body) {}

    private static final class Cursor {
        private final byte[] bytes;
        private int offset;

        private Cursor(byte[] bytes) {
            this.bytes = bytes;
        }

        private int remaining() {
            return bytes.length - offset;
        }

        private long varint() {
            if (offset >= bytes.length) {
                throw new IllegalArgumentException("truncated Binary HTTP");
            }
            int first = bytes[offset] & 0xff;
            int prefix = first >> 6;
            int length = 1 << prefix;
            if (offset + length > bytes.length) {
                throw new IllegalArgumentException("truncated Binary HTTP");
            }
            long value = 0;
            for (int i = 0; i < length; i++) {
                value = (value << 8) | (bytes[offset + i] & 0xffL);
            }
            offset += length;
            if (prefix > 0) {
                value &= (1L << (length * 8 - 2)) - 1;
            }
            return value;
        }

        private byte[] vec() {
            long length = varint();
            if (length > remaining()) {
                throw new IllegalArgumentException("truncated Binary HTTP");
            }
            int size = (int) length;
            byte[] value = java.util.Arrays.copyOfRange(bytes, offset, offset + size);
            offset += size;
            return value;
        }

        private void skipVec() {
            vec();
        }
    }
}
