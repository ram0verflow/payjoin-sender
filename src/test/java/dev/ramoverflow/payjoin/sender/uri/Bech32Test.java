package dev.ramoverflow.payjoin.sender.uri;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class Bech32Test {
    @Test
    void roundTripsUppercaseWithoutChecksum() {
        byte[] data = new byte[] {0, 1, 2, 3, 31, 32, 33, 95, 0, 96, 127, (byte) 128, (byte) 129, (byte) 254, (byte) 255, 0};
        String encoded = Bech32.encode("STUFF", data);
        assertEquals("STUFF1QQQSYQCLYQS47QRQ07QGRLHLQQ", encoded);
        assertEquals(encoded, encoded.toUpperCase());
        Bech32.Decoded decoded = Bech32.decode(encoded);
        assertEquals("STUFF", decoded.hrp());
        assertArrayEquals(data, decoded.data());
    }

    @Test
    void rejectsLowercaseData() {
        UriParseException error = assertThrows(UriParseException.class, () -> Bech32.decode("STUFF1qqq"));
        assertEquals(UriParseException.Reason.INVALID_BECH32, error.reason());
    }

    @Test
    void encodesExpirationUsedByTheReferenceTests() {
        byte[] unix = new byte[] {(byte) 0xc5, (byte) 0x79, (byte) 0x8d, (byte) 0x66};
        assertEquals("EX1C4UC6ES", Bech32.encode("EX", unix));
    }
}
