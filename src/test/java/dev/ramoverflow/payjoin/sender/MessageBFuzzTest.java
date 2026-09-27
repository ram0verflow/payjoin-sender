package dev.ramoverflow.payjoin.sender;

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Tag;
import dev.ramoverflow.payjoin.sender.crypto.Secp256k1;

/** Hostile bytes for Message B and the proposal inside it. */
@Tag("fuzz")
class MessageBFuzzTest {
    private static final byte[] REPLY = FuzzKeys.reply();
    private static final byte[] RECEIVER = Secp256k1.uncompressed(Secp256k1.compressedPublicKey(FuzzKeys.secret(8)));

    @FuzzTest(maxDuration = "30s")
    void messageB(byte[] data) {
        try {
            byte[] plaintext = Messages.decryptB(data, REPLY, RECEIVER);
            PsbtBytes.proposal(plaintext);
        } catch (IllegalArgumentException | IllegalStateException e) {
            SecretText.refuse(e, data, REPLY);
        }
    }
}
