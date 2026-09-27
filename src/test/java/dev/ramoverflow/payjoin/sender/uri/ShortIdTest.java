package dev.ramoverflow.payjoin.sender.uri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ShortIdTest {
    private static final byte[] RECEIVER_KEY = hex(
            "03db28458c699c002fe03bd4a020d037b7f286e2d65b04ebb6cb808f50f20c1596");

    @Test
    void matchesTruncatedSha256OfTheBip77ExampleKey() {
        ShortId id = ShortId.fromCompressedKey(RECEIVER_KEY);
        assertEquals("TXJCGKTKXLUUZ", id.toString());
        assertEquals(id, ShortId.parse("TXJCGKTKXLUUZ"));
    }

    @Test
    void rejectsAShortIdThatDoesNotDecodeToEightBytes() {
        assertThrows(UriParseException.class, () -> ShortId.parse("QQ"));
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
