package dev.ramoverflow.payjoin.sender;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import dev.ramoverflow.payjoin.sender.crypto.ElligatorSwift;
import dev.ramoverflow.payjoin.sender.crypto.Hpke;

/** BIP 77 messages A and B. Both are 7168 bytes on the wire. */
final class Messages {
    static final int MESSAGE_BYTES = 7168;
    static final int PLAINTEXT_B = 7088;

    private static final byte[] INFO_A = "PjV2MsgA".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] INFO_B = "PjV2MsgB".getBytes(StandardCharsets.US_ASCII);

    private Messages() {}

    static byte[] encryptA(byte[] body, byte[] replyCompressed, byte[] receiverUncompressed, Random random) {
        if (replyCompressed.length != 33) {
            throw new IllegalArgumentException("reply key must be compressed");
        }
        if (body.length > V2Body.MAX_BODY) {
            throw new IllegalArgumentException("message A payload is too large");
        }
        byte[] padded = new byte[V2Body.MAX_BODY];
        System.arraycopy(body, 0, padded, 0, body.length);
        byte[] plaintext = concat(replyCompressed, padded);
        byte[] ikm = new byte[32];
        random.nextBytes(ikm);
        Hpke.Context hpke = Hpke.setupBase(ikm, receiverUncompressed, INFO_A);
        byte[] ciphertext = Hpke.seal(hpke, new byte[0], plaintext);
        return concat(ElligatorSwift.encode(hpke.encapsulatedKey(), random), ciphertext);
    }

    static byte[] decryptB(byte[] message, byte[] replySecret, byte[] receiverUncompressed) {
        if (message.length != MESSAGE_BYTES) {
            throw new IllegalArgumentException("message B must be 7168 bytes");
        }
        byte[] encapsulated = ElligatorSwift.decode(Arrays.copyOf(message, 64));
        byte[] ciphertext = Arrays.copyOfRange(message, 64, message.length);
        byte[] plaintext = Hpke.open(replySecret, receiverUncompressed, encapsulated, INFO_B, new byte[0], ciphertext);
        if (plaintext.length != PLAINTEXT_B) {
            throw new InternalException("message B plaintext is the wrong length");
        }
        return plaintext;
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] out = new byte[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }
}
