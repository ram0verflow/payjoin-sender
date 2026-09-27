package org.payjoin.sender;

import java.nio.charset.StandardCharsets;
import org.payjoin.sender.crypto.ChaCha20Poly1305;
import org.payjoin.sender.crypto.Hkdf;
import org.payjoin.sender.crypto.Hpke;
import org.payjoin.sender.ohttp.Ohttp;

/** Builds an 8192-byte directory response the session can decapsulate. */
final class DirectoryResponse {
    private DirectoryResponse() {}

    static byte[] seal(Ohttp.Context context, int status, byte[] body) {
        byte[] message = response(status, body);
        byte[] plaintext = new byte[Ohttp.ENCAPSULATED_LEN - 32 - 16];
        System.arraycopy(message, 0, plaintext, 0, message.length);
        byte[] nonce = new byte[32];
        nonce[0] = 9;
        byte[] secret = Hpke.export(
                new Hpke.Context(context.encapsulatedKey(), null, null, context.exporterSecret()),
                "message/bhttp response".getBytes(StandardCharsets.US_ASCII),
                32);
        byte[] salt = new byte[context.encapsulatedKey().length + nonce.length];
        System.arraycopy(context.encapsulatedKey(), 0, salt, 0, context.encapsulatedKey().length);
        System.arraycopy(nonce, 0, salt, context.encapsulatedKey().length, nonce.length);
        byte[] prk = Hkdf.extract(salt, secret);
        byte[] key = Hkdf.expand(prk, "key".getBytes(StandardCharsets.US_ASCII), 32);
        byte[] iv = Hkdf.expand(prk, "nonce".getBytes(StandardCharsets.US_ASCII), 12);
        byte[] sealed = ChaCha20Poly1305.seal(key, iv, new byte[0], plaintext);
        byte[] encapsulated = new byte[Ohttp.ENCAPSULATED_LEN];
        System.arraycopy(nonce, 0, encapsulated, 0, nonce.length);
        System.arraycopy(sealed, 0, encapsulated, nonce.length, sealed.length);
        return encapsulated;
    }

    private static byte[] response(int status, byte[] body) {
        byte[] out = new byte[1 + 2 + 1 + varintLength(body.length) + body.length + 1];
        int i = 0;
        out[i++] = 1;
        i = varint(out, i, status);
        out[i++] = 0;
        i = varint(out, i, body.length);
        System.arraycopy(body, 0, out, i, body.length);
        i += body.length;
        out[i] = 0;
        return out;
    }

    private static int varint(byte[] out, int offset, int value) {
        if (value < 64) {
            out[offset] = (byte) value;
            return offset + 1;
        }
        int encoded = value | (1 << 14);
        out[offset] = (byte) (encoded >> 8);
        out[offset + 1] = (byte) encoded;
        return offset + 2;
    }

    private static int varintLength(int value) {
        return value < 64 ? 1 : 2;
    }
}
