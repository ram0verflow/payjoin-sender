package org.payjoin.sender;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Tag;

/** Hostile bytes for a session log line. */
@Tag("fuzz")
class SessionLogFuzzTest {
    private static final byte[] REPLY = FuzzKeys.reply();

    @FuzzTest(maxDuration = "30s")
    void sessionLog(byte[] data) {
        try {
            EventLog.parse(new String(data, StandardCharsets.ISO_8859_1));
        } catch (IllegalArgumentException e) {
            SecretText.refuse(e, data, REPLY);
        }
    }
}
