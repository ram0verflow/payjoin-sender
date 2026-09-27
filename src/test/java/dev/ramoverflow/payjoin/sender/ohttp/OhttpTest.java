package dev.ramoverflow.payjoin.sender.ohttp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import dev.ramoverflow.payjoin.sender.crypto.ChaCha20Poly1305;
import dev.ramoverflow.payjoin.sender.crypto.Hkdf;
import dev.ramoverflow.payjoin.sender.crypto.Hpke;
import dev.ramoverflow.payjoin.sender.crypto.Secp256k1;

/** Test-only OHTTP key. Do not use this scalar as a wallet. */
class OhttpTest {
    /** Test-only secp256k1 scalar. Not a wallet key. */
    private static final byte[] RECEIVER = hex("4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643");

    @Test
    void keyConfigRebuildsTheRfc9458Encoding() {
        byte[] compressed = Secp256k1.compressedPublicKey(RECEIVER);
        byte[] encoded = new byte[34];
        encoded[0] = 0x01;
        System.arraycopy(compressed, 0, encoded, 1, 33);
        OhttpKeys keys = OhttpKeys.parse(encoded);
        byte[] config = keys.keyConfig();
        assertEquals(74, config.length);
        assertEquals(0x01, config[0]);
        assertEquals(0x00, config[1]);
        assertEquals(0x16, config[2]);
        assertArrayEquals(Secp256k1.uncompressed(compressed), Arrays.copyOfRange(config, 3, 68));
        assertArrayEquals(hex("000400010003"), Arrays.copyOfRange(config, 68, 74));
    }

    @Test
    void keyConfigRejectsTheWrongShape() {
        assertThrows(IllegalArgumentException.class, () -> OhttpKeys.parse(new byte[33]));
        byte[] badPrefix = new byte[34];
        badPrefix[1] = 0x04;
        assertThrows(IllegalArgumentException.class, () -> OhttpKeys.parse(badPrefix));
        byte[] offCurve = new byte[34];
        offCurve[1] = 0x02;
        offCurve[2] = 0x01;
        assertThrows(IllegalArgumentException.class, () -> OhttpKeys.parse(offCurve));
    }

    @Test
    void binaryHttpRequestMatchesTheKnownLengthEncoding() {
        byte[] body = new byte[] {1, 2, 3};
        byte[] encoded = Bhttp.request("POST", "https", "payjo.in", "/TXJCGKTKXLUUZ", body);
        assertArrayEquals(
                hex("0004504f5354056874747073087061796a6f2e696e0e2f54584a43474b544b584c55555a000301020300"),
                encoded);
        byte[] get = Bhttp.request("GET", "https", "payjo.in", "/TXJCGKTKXLUUZ", body);
        assertArrayEquals(
                hex("0003474554056874747073087061796a6f2e696e0e2f54584a43474b544b584c55555a000301020300"),
                get);
        byte[] padded = Bhttp.responseBytes(200, new byte[] {4, 5});
        byte[] withPadding = new byte[padded.length + 8];
        System.arraycopy(padded, 0, withPadding, 0, padded.length);
        Bhttp.Reply reply = Bhttp.response(withPadding);
        assertEquals(200, reply.status());
        assertArrayEquals(new byte[] {4, 5}, reply.body());
        assertThrows(IllegalArgumentException.class, () -> Bhttp.response(new byte[] {0x01}));
        assertThrows(IllegalArgumentException.class, () -> Bhttp.response(Arrays.copyOf(padded, padded.length - 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> Bhttp.response(new byte[] {
                    0x01, (byte) 0xff, (byte) 0xff, 0x01, 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff
                }));
    }

    @Test
    void encapsulateProduces8192BytesAndTheReceiverCanOpenIt() {
        OhttpKeys keys = keys();
        byte[] body = new byte[] {9, 8, 7};
        Ohttp.Request request = Ohttp.encapsulate(
                keys, "POST", "https://payjo.in:443/TXJCGKTKXLUUZ", body, new Random(1));
        assertEquals(Ohttp.ENCAPSULATED_LEN, request.encapsulated().length);
        assertArrayEquals(new byte[] {0x01, 0x00, 0x16, 0x00, 0x01, 0x00, 0x03}, Arrays.copyOf(request.encapsulated(), 7));
        byte[] info = concat(
                "message/bhttp request".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                new byte[] {0},
                Arrays.copyOf(request.encapsulated(), 7));
        byte[] encapsulatedKey = Arrays.copyOfRange(request.encapsulated(), 7, 72);
        byte[] ciphertext = Arrays.copyOfRange(request.encapsulated(), 72, request.encapsulated().length);
        byte[] padded = Hpke.open(RECEIVER, null, encapsulatedKey, info, new byte[0], ciphertext);
        assertEquals(Ohttp.PADDED_REQUEST_LEN, padded.length);
        byte[] expected = Bhttp.request("POST", "https", "payjo.in:443", "/TXJCGKTKXLUUZ", body);
        assertArrayEquals(expected, Arrays.copyOf(padded, expected.length));
    }

    @Test
    void decapsulateReadsTheBinaryHttpResponseAndRejectsTampering() {
        Ohttp.Request request = Ohttp.encapsulate(keys(), "POST", "https://payjo.in/id", new byte[] {1}, new Random(2));
        byte[] nonce = new byte[32];
        nonce[0] = 7;
        byte[] responsePlaintext = new byte[Ohttp.ENCAPSULATED_LEN - 32 - 16];
        byte[] message = Bhttp.responseBytes(200, new byte[] {4, 5});
        System.arraycopy(message, 0, responsePlaintext, 0, message.length);
        byte[] sealed = sealResponse(request.context(), nonce, responsePlaintext);
        byte[] encapsulated = new byte[Ohttp.ENCAPSULATED_LEN];
        System.arraycopy(nonce, 0, encapsulated, 0, nonce.length);
        System.arraycopy(sealed, 0, encapsulated, nonce.length, sealed.length);

        Ohttp.Reply reply = Ohttp.decapsulate(request.context(), encapsulated);
        assertEquals(200, reply.status());
        assertArrayEquals(new byte[] {4, 5}, reply.body());

        encapsulated[40] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> Ohttp.decapsulate(request.context(), encapsulated));
        assertThrows(IllegalArgumentException.class, () -> Ohttp.decapsulate(request.context(), new byte[10]));
    }

    private static byte[] sealResponse(Ohttp.Context context, byte[] nonce, byte[] plaintext) {
        byte[] secret = Hpke.export(
                new Hpke.Context(context.encapsulatedKey(), null, null, context.exporterSecret()),
                "message/bhttp response".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                32);
        byte[] prk = Hkdf.extract(concat(context.encapsulatedKey(), nonce), secret);
        byte[] key = Hkdf.expand(prk, "key".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 32);
        byte[] iv = Hkdf.expand(prk, "nonce".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 12);
        return ChaCha20Poly1305.seal(key, iv, new byte[0], plaintext);
    }

    private static OhttpKeys keys() {
        byte[] compressed = Secp256k1.compressedPublicKey(RECEIVER);
        byte[] encoded = new byte[34];
        encoded[0] = 0x01;
        System.arraycopy(compressed, 0, encoded, 1, 33);
        return OhttpKeys.parse(encoded);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
