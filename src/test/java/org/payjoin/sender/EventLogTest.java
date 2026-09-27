package org.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class EventLogTest {
    @Test
    void roundTripsEachEvent() {
        EventLog.Event created = new EventLog.Event("created");
        created.reply = "aa";
        created.psbt = "cHNidA==";
        created.payee = "0014";
        created.endpoint = "https://payjo.in/ID";
        created.expiry = 1_700_000_000L;
        created.ohttp = "01";
        created.receiver = "02";
        created.substitution = true;
        created.feeIndex = 1;
        created.feeSats = 1000L;
        created.minFee = 2L;
        assertRoundTrip(EventLog.created(created));
        assertRoundTrip(EventLog.posted());
        assertRoundTrip(EventLog.cancelled());
        assertRoundTrip(EventLog.closed("success", "cHNidA=="));
        assertRoundTrip(EventLog.closed("aborted", null));
    }

    @Test
    void acceptsSpacesBetweenTokens() {
        EventLog.Event event = EventLog.parse("{ \"v\" : 1 , \"type\" : \"posted\" }");
        assertEquals("posted", event.type);
    }

    @Test
    void rejectsHostileLines() {
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("not json"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"type\":\"posted\"}{}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"v\":1,\"type\":\"posted\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"type\":\"posted\",\"extra\":1}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"type\":\"posted\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":01,\"type\":\"posted\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1.0,\"type\":\"posted\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1e2,\"type\":\"posted\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":{},\"type\":\"posted\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"type\":\"a\\nb\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"type\":\"posted\"}\n"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"type\":\"posted\u0001\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":1,\"type\":\"posted\u00e9\"}"));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("a".repeat(EventLog.MAX_LINE_BYTES + 1)));
        assertThrows(IllegalArgumentException.class, () -> EventLog.parse("{\"v\":2,\"type\":\"posted\"}"));
    }

    private static void assertRoundTrip(String line) {
        assertEquals(line, EventLog.write(EventLog.parse(line)));
    }
}
