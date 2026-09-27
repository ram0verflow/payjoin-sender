package dev.ramoverflow.payjoin.sender.ohttp;

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Tag;
import dev.ramoverflow.payjoin.sender.FuzzKeys;
import dev.ramoverflow.payjoin.sender.SecretText;

/** Hostile bytes for a Binary HTTP response. */
@Tag("fuzz")
class BhttpFuzzTest {
    @FuzzTest(maxDuration = "30s")
    void binaryHttp(byte[] data) {
        try {
            Bhttp.response(data);
        } catch (IllegalArgumentException e) {
            SecretText.refuse(e, data, FuzzKeys.reply());
        }
    }
}
