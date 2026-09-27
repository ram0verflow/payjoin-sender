package dev.ramoverflow.payjoin.sender.ohttp;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import dev.ramoverflow.payjoin.sender.crypto.ChaCha20Poly1305;
import dev.ramoverflow.payjoin.sender.crypto.Hkdf;
import dev.ramoverflow.payjoin.sender.crypto.Hpke;

/**
 * Oblivious HTTP for a BIP 77 sender. Encapsulation is 8192 bytes.
 * The caller supplies randomness; production code passes {@code SecureRandom}.
 */
public final class Ohttp {
    /** Fixed size of an encapsulated request or response. */
    public static final int ENCAPSULATED_LEN = 8192;
    static final int PADDED_REQUEST_LEN = 8104;
    private static final byte[] INFO_REQUEST = "message/bhttp request".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_RESPONSE = "message/bhttp response".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] INFO_KEY = "key".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] INFO_NONCE = "nonce".getBytes(StandardCharsets.US_ASCII);

    private Ohttp() {}

    /** Encapsulated request bytes and the context needed to open the response. */
    public record Request(byte[] encapsulated, Context context) {}

    /** Directory status and body after the response is opened. */
    public record Reply(int status, byte[] body) {}

    /**
     * Held between encapsulation and the matching response.
     * {@code exporterSecret} is the HPKE export secret for the response key.
     */
    public record Context(byte[] encapsulatedKey, byte[] exporterSecret) {}

    /** Encapsulates one Binary HTTP request to {@code target}. */
    public static Request encapsulate(OhttpKeys keys, String method, String target, byte[] body, Random random) {
        URI uri = URI.create(target);
        if (uri.getScheme() == null || uri.getHost() == null || uri.getRawPath() == null) {
            throw new IllegalArgumentException("OHTTP target must be an absolute URL");
        }
        String scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw new IllegalArgumentException("OHTTP target scheme must be http or https");
        }
        String authority = uri.getHost().toLowerCase(java.util.Locale.ROOT);
        if (uri.getPort() != -1) {
            authority = authority + ":" + uri.getPort();
        }
        String path = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        byte[] encoded = Bhttp.request(method, scheme, authority, path, body == null ? new byte[0] : body);
        if (encoded.length > PADDED_REQUEST_LEN) {
            throw new IllegalArgumentException("OHTTP request does not fit in the padded message");
        }
        byte[] padded = new byte[PADDED_REQUEST_LEN];
        random.nextBytes(padded);
        System.arraycopy(encoded, 0, padded, 0, encoded.length);

        byte[] header = header(keys);
        byte[] info = concat(INFO_REQUEST, new byte[] {0}, header);
        byte[] ikm = new byte[32];
        random.nextBytes(ikm);
        Hpke.Context hpke = Hpke.setupBase(ikm, keys.publicKey(), info);
        byte[] ciphertext = Hpke.seal(hpke, new byte[0], padded);
        byte[] encapsulated = concat(header, hpke.encapsulatedKey(), ciphertext);
        if (encapsulated.length != ENCAPSULATED_LEN) {
            throw new IllegalStateException("OHTTP request is not 8192 bytes");
        }
        return new Request(encapsulated, new Context(hpke.encapsulatedKey(), hpke.exporterSecret()));
    }

    /** Opens an 8192-byte response and reads its Binary HTTP message. */
    public static Reply decapsulate(Context context, byte[] encapsulated) {
        if (encapsulated.length != ENCAPSULATED_LEN) {
            throw new IllegalArgumentException("OHTTP response must be 8192 bytes");
        }
        byte[] nonce = Arrays.copyOf(encapsulated, 32);
        byte[] ciphertext = Arrays.copyOfRange(encapsulated, 32, encapsulated.length);
        byte[] secret = Hpke.export(
                new Hpke.Context(context.encapsulatedKey, null, null, context.exporterSecret), LABEL_RESPONSE, 32);
        byte[] prk = Hkdf.extract(concat(context.encapsulatedKey, nonce), secret);
        byte[] key = Hkdf.expand(prk, INFO_KEY, 32);
        byte[] iv = Hkdf.expand(prk, INFO_NONCE, 12);
        byte[] plaintext;
        try {
            plaintext = ChaCha20Poly1305.open(key, iv, new byte[0], ciphertext);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("OHTTP response failed to open", e);
        }
        Bhttp.Reply reply = Bhttp.response(plaintext);
        return new Reply(reply.status(), reply.body());
    }

    private static byte[] header(OhttpKeys keys) {
        return new byte[] {keys.keyId(), 0x00, 0x16, 0x00, 0x01, 0x00, 0x03};
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
}
