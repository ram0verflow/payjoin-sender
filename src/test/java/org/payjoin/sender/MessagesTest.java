package org.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.payjoin.sender.crypto.ElligatorSwift;
import org.payjoin.sender.crypto.Hpke;
import org.payjoin.sender.crypto.Secp256k1;

class MessagesTest {
    @Test
    void messageACarriesTheReplyKeyAndThePaddedBody() {
        byte[] receiver = secret(1);
        byte[] reply = secret(2);
        byte[] body = "psbt\nv=2".getBytes(StandardCharsets.US_ASCII);
        byte[] message = Messages.encryptA(
                body, Secp256k1.compressedPublicKey(reply), Secp256k1.publicKey(receiver), new Random(1));
        assertEquals(Messages.MESSAGE_BYTES, message.length);
        byte[] plain = openA(message, receiver);
        assertArrayEquals(Secp256k1.compressedPublicKey(reply), Arrays.copyOf(plain, 33));
        assertArrayEquals(body, Arrays.copyOfRange(plain, 33, 33 + body.length));
        assertEquals(0, plain[plain.length - 1]);
        message[70] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> openA(message, receiver));
    }

    private static byte[] openA(byte[] message, byte[] receiverSecret) {
        return Hpke.open(
                receiverSecret,
                null,
                ElligatorSwift.decode(Arrays.copyOf(message, 64)),
                "PjV2MsgA".getBytes(StandardCharsets.US_ASCII),
                new byte[0],
                Arrays.copyOfRange(message, 64, message.length));
    }

    @Test
    void anEmptyPollPayloadIsTheReplyKeyFollowedByZeros() {
        byte[] receiver = secret(5);
        byte[] reply = secret(6);
        byte[] message = Messages.encryptA(
                new byte[0], Secp256k1.compressedPublicKey(reply), Secp256k1.publicKey(receiver), new Random(8));
        assertEquals(Messages.MESSAGE_BYTES, message.length);
        byte[] plain = openA(message, receiver);
        assertArrayEquals(Secp256k1.compressedPublicKey(reply), Arrays.copyOf(plain, 33));
        for (int i = 33; i < plain.length; i++) {
            assertEquals(0, plain[i]);
        }
    }

    @Test
    void messageBOpensWithTheReplyKeyAndRejectsABadTag() {
        byte[] receiver = secret(3);
        byte[] reply = secret(4);
        byte[] payload = PsbtBytesTest.minimalPsbt();
        byte[] message = sealB(payload, receiver, reply, new Random(2));
        byte[] plain = Messages.decryptB(message, reply, Secp256k1.publicKey(receiver));
        assertArrayEquals(payload, Arrays.copyOf(plain, payload.length));
        assertEquals(0, plain[plain.length - 1]);
        message[80] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> Messages.decryptB(message, reply, Secp256k1.publicKey(receiver)));
        assertThrows(IllegalArgumentException.class, () -> Messages.encryptA(
                new byte[V2Body.MAX_BODY + 1],
                Secp256k1.compressedPublicKey(reply),
                Secp256k1.publicKey(receiver),
                new Random(3)));
    }

    static byte[] sealB(byte[] payload, byte[] receiverSecret, byte[] replySecret, Random random) {
        byte[] padded = new byte[Messages.PLAINTEXT_B];
        System.arraycopy(payload, 0, padded, 0, payload.length);
        byte[] ikm = new byte[32];
        random.nextBytes(ikm);
        Hpke.Context hpke = Hpke.setupAuth(
                ikm, receiverSecret, Secp256k1.publicKey(replySecret), "PjV2MsgB".getBytes(StandardCharsets.US_ASCII));
        byte[] ciphertext = Hpke.seal(hpke, new byte[0], padded);
        byte[] ellswift = ElligatorSwift.encode(hpke.encapsulatedKey(), random);
        byte[] message = new byte[ellswift.length + ciphertext.length];
        System.arraycopy(ellswift, 0, message, 0, ellswift.length);
        System.arraycopy(ciphertext, 0, message, ellswift.length, ciphertext.length);
        return message;
    }

    private static byte[] secret(int tag) {
        byte[] secret = new byte[32];
        secret[31] = (byte) tag;
        return secret;
    }
}
