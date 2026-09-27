package dev.ramoverflow.payjoin.sender;

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Tag;

/** Hostile bytes for the PSBT reader. */
@Tag("fuzz")
class PsbtFuzzTest {
    private static final byte[] REPLY = FuzzKeys.reply();

    @FuzzTest(maxDuration = "30s")
    void psbt(byte[] data) {
        try {
            Psbt.read(data);
        } catch (IllegalArgumentException e) {
            SecretText.refuse(e, data, REPLY);
        }
        try {
            PsbtBytes.proposal(data);
        } catch (IllegalArgumentException | CounterpartyException e) {
            SecretText.refuse(e, data, REPLY);
        }
    }
}
