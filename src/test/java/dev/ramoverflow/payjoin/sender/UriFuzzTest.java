package dev.ramoverflow.payjoin.sender;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Tag;
import dev.ramoverflow.payjoin.sender.uri.PayjoinUri;

/** Hostile bytes for a Payjoin URI. */
@Tag("fuzz")
class UriFuzzTest {
    private static final byte[] REPLY = FuzzKeys.reply();

    @FuzzTest(maxDuration = "30s")
    void uri(byte[] data) {
        try {
            PayjoinUri parsed = PayjoinUri.parse(new String(data, StandardCharsets.ISO_8859_1));
            AddressScript.script(parsed.address());
        } catch (IllegalArgumentException e) {
            SecretText.refuse(e, data, REPLY);
        }
    }
}
