package dev.ramoverflow.payjoin.sender.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Sender directions against bitcoin-hpke 0.13.0, at the HPKE plaintext
 * sizes rust-payjoin seals. Message A is 33-byte reply key plus a body
 * padded to 7055, so 7088 bytes. Message B is padded to 7088 bytes.
 * Both sit inside a 7168-byte message after the 64-byte ElligatorSwift
 * encoding and the 16-byte tag.
 */
@Tag("oracle")
/** Test-only HPKE vectors. Do not use these scalars as wallets. */
class HpkeOracleTest {
    private static final int MESSAGE_PLAINTEXT = 7088;
    private static final byte[] INFO_A = "PjV2MsgA".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] INFO_B = "PjV2MsgB".getBytes(StandardCharsets.US_ASCII);
    private static final Path HARNESS = Path.of("src/test/rust/hpke-oracle");

    @Test
    void bitcoinHpkeOpensJavaBaseSealAtMessageASize() throws Exception {
        byte[] receiverSecret = hex("4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643");
        byte[] ikmE = hex("77caf1617fb3723972a56cd2085081c9f66baae825ce5f363c0a86ec87013fa0");
        byte[] plaintext = messagePlaintext((byte) 0xA1);
        Hpke.Context context = Hpke.setupBase(ikmE, Secp256k1.publicKey(receiverSecret), INFO_A);
        byte[] sealed = Hpke.seal(context, new byte[0], plaintext);
        assertEquals(MESSAGE_PLAINTEXT + 16, sealed.length);

        byte[] opened = openBase(receiverSecret, context.encapsulatedKey(), INFO_A, sealed);
        assertArrayEquals(plaintext, opened);

        byte[] tampered = sealed.clone();
        tampered[tampered.length / 2] ^= 1;
        assertEquals(1, openBaseStatus(receiverSecret, context.encapsulatedKey(), INFO_A, tampered));
    }

    @Test
    void javaOpensBitcoinHpkeAuthSealAtMessageBSize() throws Exception {
        byte[] senderSecret = hex("1300156862599d00ecbb066644bf4d4505b56a9b235eae7a8632defc4335d5c0");
        byte[] receiverSecret = hex("4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643");
        byte[] ikmE = hex("f402a160b0dd43a5490e9315dd8ea386eb3b2bde9e252857e8a3132fa084506b");
        byte[] plaintext = messagePlaintext((byte) 0xB2);
        byte[] response = sealAuth(ikmE, receiverSecret, Secp256k1.publicKey(senderSecret), INFO_B, plaintext);
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(response));
        byte[] encapsulated = in.readNBytes(65);
        int length = in.readInt();
        byte[] sealed = in.readNBytes(length);
        assertEquals(0, in.available());
        assertEquals(MESSAGE_PLAINTEXT + 16, sealed.length);

        assertArrayEquals(
                plaintext,
                Hpke.open(senderSecret, Secp256k1.publicKey(receiverSecret), encapsulated, INFO_B, new byte[0], sealed));
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 1;
        assertThrows(
                IllegalArgumentException.class,
                () -> Hpke.open(
                        senderSecret, Secp256k1.publicKey(receiverSecret), encapsulated, INFO_B, new byte[0], tampered));
    }

    private static byte[] messagePlaintext(byte marker) {
        byte[] plaintext = new byte[MESSAGE_PLAINTEXT];
        plaintext[0] = 0x02;
        plaintext[32] = marker;
        plaintext[33] = 0x01;
        plaintext[MESSAGE_PLAINTEXT - 1] = marker;
        return plaintext;
    }

    private static byte[] openBase(byte[] secret, byte[] encapsulated, byte[] info, byte[] ciphertext) throws Exception {
        byte[] response = run("open-base", frame(secret, encapsulated, info, ciphertext));
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(response));
        assertEquals(0, in.readUnsignedByte(), "bitcoin-hpke rejected a genuine base ciphertext");
        int length = in.readInt();
        byte[] plaintext = in.readNBytes(length);
        assertEquals(0, in.available());
        return plaintext;
    }

    private static int openBaseStatus(byte[] secret, byte[] encapsulated, byte[] info, byte[] ciphertext)
            throws Exception {
        byte[] response = run("open-base", frame(secret, encapsulated, info, ciphertext));
        return new DataInputStream(new ByteArrayInputStream(response)).readUnsignedByte();
    }

    private static byte[] sealAuth(
            byte[] ikmE, byte[] senderSecret, byte[] recipientPublic, byte[] info, byte[] plaintext) throws Exception {
        return run("seal-auth", frame(ikmE, senderSecret, recipientPublic, info, plaintext));
    }

    private static byte[] frame(byte[] first, byte[] second, byte[] third, byte[] fourth, byte[] fifth)
            throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(first);
        bytes.write(second);
        bytes.write(third);
        new DataOutputStream(bytes).writeInt(fourth.length);
        bytes.write(fourth);
        new DataOutputStream(bytes).writeInt(fifth.length);
        bytes.write(fifth);
        return bytes.toByteArray();
    }

    private static byte[] frame(byte[] secret, byte[] encapsulated, byte[] info, byte[] ciphertext) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(secret);
        bytes.write(encapsulated);
        new DataOutputStream(bytes).writeInt(info.length);
        bytes.write(info);
        new DataOutputStream(bytes).writeInt(ciphertext.length);
        bytes.write(ciphertext);
        return bytes.toByteArray();
    }

    private static byte[] run(String command, byte[] stdin) throws Exception {
        Process process = new ProcessBuilder("cargo", "run", "--quiet", "--locked", "--", command)
                .directory(HARNESS.toFile())
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        process.getOutputStream().write(stdin);
        process.getOutputStream().close();
        byte[] stdout = process.getInputStream().readAllBytes();
        if (!process.waitFor(3, TimeUnit.MINUTES)) {
            process.destroyForcibly();
            throw new IllegalStateException("hpke-oracle timed out");
        }
        if (process.exitValue() != 0) {
            throw new IllegalStateException("hpke-oracle exited " + process.exitValue());
        }
        return stdout;
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
