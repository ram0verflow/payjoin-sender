package org.payjoin.sender;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Version-1 session lines. Internal. Not a general JSON parser. */
final class EventLog {
    static final int MAX_LINE_BYTES = 65536;

    private static final Set<String> CREATED_KEYS = Set.of(
            "v", "type", "reply", "psbt", "endpoint", "expiry", "ohttp", "receiver", "substitution",
            "feeIndex", "feeSats", "minFee");
    private static final Set<String> CLOSED_KEYS = Set.of("v", "type", "outcome", "proposal");
    private static final Set<String> BARE_KEYS = Set.of("v", "type");

    private EventLog() {}

    static String created(Event event) {
        StringBuilder out = new StringBuilder();
        out.append("{\"v\":1,\"type\":\"created\"");
        stringField(out, "reply", event.reply);
        stringField(out, "psbt", event.psbt);
        stringField(out, "endpoint", event.endpoint);
        out.append(",\"expiry\":").append(event.expiry);
        stringField(out, "ohttp", event.ohttp);
        stringField(out, "receiver", event.receiver);
        out.append(",\"substitution\":").append(event.substitution);
        if (event.feeIndex != null) {
            out.append(",\"feeIndex\":").append(event.feeIndex);
            out.append(",\"feeSats\":").append(event.feeSats);
        }
        if (event.minFee != null) {
            out.append(",\"minFee\":").append(event.minFee);
        }
        out.append('}');
        return finish(out);
    }

    static String posted() {
        return "{\"v\":1,\"type\":\"posted\"}";
    }

    static String cancelled() {
        return "{\"v\":1,\"type\":\"cancelled\"}";
    }

    static String write(Event event) {
        return switch (event.type) {
            case "created" -> created(event);
            case "posted" -> posted();
            case "cancelled" -> cancelled();
            case "closed" -> closed(event.outcome, event.proposal);
            default -> throw new IllegalArgumentException("unknown session event");
        };
    }

    static String closed(String outcome, String proposal) {
        StringBuilder out = new StringBuilder();
        out.append("{\"v\":1,\"type\":\"closed\",\"outcome\":\"").append(outcome).append('"');
        if (proposal != null) {
            stringField(out, "proposal", proposal);
        }
        out.append('}');
        return finish(out);
    }

    static Event parse(String line) {
        if (line == null) {
            throw new IllegalArgumentException("session line is missing");
        }
        if (line.length() > MAX_LINE_BYTES) {
            throw new IllegalArgumentException("session line is too long");
        }
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                throw new IllegalArgumentException("session line contains a control or non-ASCII byte");
            }
        }
        Parser parser = new Parser(line);
        parser.skipSpaces();
        parser.expect('{');
        Map<String, Value> fields = new LinkedHashMap<>();
        parser.skipSpaces();
        if (!parser.peek('}')) {
            while (true) {
                String key = parser.string();
                if (fields.containsKey(key)) {
                    throw new IllegalArgumentException("duplicate session key");
                }
                parser.skipSpaces();
                parser.expect(':');
                parser.skipSpaces();
                fields.put(key, parser.value());
                parser.skipSpaces();
                if (parser.peek('}')) {
                    break;
                }
                parser.expect(',');
                parser.skipSpaces();
            }
        }
        parser.expect('}');
        parser.skipSpaces();
        if (!parser.done()) {
            throw new IllegalArgumentException("trailing data after session object");
        }
        return interpret(fields);
    }

    private static Event interpret(Map<String, Value> fields) {
        Value version = required(fields, "v");
        if (!(version instanceof Value.Num) || ((Value.Num) version).value != 1L) {
            throw new IllegalArgumentException("unknown session version");
        }
        String type = text(required(fields, "type"), "type");
        return switch (type) {
            case "created" -> createdEvent(fields);
            case "posted" -> bare(fields, "posted");
            case "cancelled" -> bare(fields, "cancelled");
            case "closed" -> closedEvent(fields);
            default -> throw new IllegalArgumentException("unknown session event");
        };
    }

    private static Event createdEvent(Map<String, Value> fields) {
        rejectUnknown(fields, CREATED_KEYS);
        Event event = new Event("created");
        event.reply = text(required(fields, "reply"), "reply");
        event.psbt = text(required(fields, "psbt"), "psbt");
        event.endpoint = text(required(fields, "endpoint"), "endpoint");
        event.expiry = nonNegative(required(fields, "expiry"), "expiry");
        event.ohttp = text(required(fields, "ohttp"), "ohttp");
        event.receiver = text(required(fields, "receiver"), "receiver");
        Value substitution = required(fields, "substitution");
        if (!(substitution instanceof Value.Bool)) {
            throw new IllegalArgumentException("substitution must be a boolean");
        }
        event.substitution = ((Value.Bool) substitution).value;
        boolean feeIndex = fields.containsKey("feeIndex");
        boolean feeSats = fields.containsKey("feeSats");
        if (feeIndex != feeSats) {
            throw new IllegalArgumentException("fee contribution needs both an amount and an output index");
        }
        if (feeIndex) {
            long index = nonNegative(fields.get("feeIndex"), "feeIndex");
            if (index > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("feeIndex is out of range");
            }
            event.feeIndex = (int) index;
            event.feeSats = nonNegative(fields.get("feeSats"), "feeSats");
        }
        if (fields.containsKey("minFee")) {
            event.minFee = nonNegative(fields.get("minFee"), "minFee");
        }
        return event;
    }

    private static Event bare(Map<String, Value> fields, String type) {
        rejectUnknown(fields, BARE_KEYS);
        return new Event(type);
    }

    private static Event closedEvent(Map<String, Value> fields) {
        rejectUnknown(fields, CLOSED_KEYS);
        String outcome = text(required(fields, "outcome"), "outcome");
        Event event = new Event("closed");
        event.outcome = outcome;
        if (outcome.equals("success")) {
            event.proposal = text(required(fields, "proposal"), "proposal");
        } else if (outcome.equals("aborted")) {
            if (fields.containsKey("proposal")) {
                throw new IllegalArgumentException("aborted session has a proposal");
            }
        } else {
            throw new IllegalArgumentException("unknown session outcome");
        }
        return event;
    }

    private static void rejectUnknown(Map<String, Value> fields, Set<String> allowed) {
        for (String key : fields.keySet()) {
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException("unknown session key");
            }
        }
    }

    private static Value required(Map<String, Value> fields, String key) {
        Value value = fields.get(key);
        if (value == null) {
            throw new IllegalArgumentException("missing session key");
        }
        return value;
    }

    private static String text(Value value, String key) {
        if (!(value instanceof Value.Str)) {
            throw new IllegalArgumentException(key + " must be a string");
        }
        return ((Value.Str) value).value;
    }

    private static long nonNegative(Value value, String key) {
        if (!(value instanceof Value.Num)) {
            throw new IllegalArgumentException(key + " must be an integer");
        }
        long number = ((Value.Num) value).value;
        if (number < 0) {
            throw new IllegalArgumentException(key + " must be non-negative");
        }
        return number;
    }

    private static void stringField(StringBuilder out, String key, String value) {
        writable(value);
        out.append(",\"").append(key).append("\":\"").append(value).append('"');
    }

    private static void writable(String value) {
        if (value == null) {
            throw new IllegalArgumentException("session string is missing");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
                throw new IllegalArgumentException("session string cannot be written");
            }
        }
    }

    private static String finish(StringBuilder out) {
        if (out.length() > MAX_LINE_BYTES) {
            throw new IllegalArgumentException("session line is too long");
        }
        return out.toString();
    }

    static final class Event {
        final String type;
        String reply;
        String psbt;
        String endpoint;
        long expiry;
        String ohttp;
        String receiver;
        boolean substitution;
        Integer feeIndex;
        Long feeSats;
        Long minFee;
        String outcome;
        String proposal;

        Event(String type) {
            this.type = type;
        }
    }

    private abstract static class Value {
        private static final class Str extends Value {
            final String value;

            private Str(String value) {
                this.value = value;
            }
        }

        private static final class Num extends Value {
            final long value;

            private Num(long value) {
                this.value = value;
            }
        }

        private static final class Bool extends Value {
            final boolean value;

            private Bool(boolean value) {
                this.value = value;
            }
        }
    }

    private static final class Parser {
        private final String line;
        private int index;

        private Parser(String line) {
            this.line = line;
        }

        private void skipSpaces() {
            while (index < line.length() && line.charAt(index) == ' ') {
                index++;
            }
        }

        private boolean peek(char expected) {
            return index < line.length() && line.charAt(index) == expected;
        }

        private boolean done() {
            return index == line.length();
        }

        private void expect(char expected) {
            if (!peek(expected)) {
                throw new IllegalArgumentException("malformed session line");
            }
            index++;
        }

        private String string() {
            expect('"');
            int start = index;
            while (index < line.length()) {
                char c = line.charAt(index);
                if (c == '"') {
                    String value = line.substring(start, index);
                    index++;
                    return value;
                }
                if (c == '\\') {
                    throw new IllegalArgumentException("session string contains an escape");
                }
                index++;
            }
            throw new IllegalArgumentException("truncated session line");
        }

        private Value value() {
            if (index >= line.length()) {
                throw new IllegalArgumentException("truncated session line");
            }
            char c = line.charAt(index);
            if (c == '"') {
                return new Value.Str(string());
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return new Value.Num(number());
            }
            if (line.startsWith("true", index)) {
                index += 4;
                return new Value.Bool(true);
            }
            if (line.startsWith("false", index)) {
                index += 5;
                return new Value.Bool(false);
            }
            if (c == '{' || c == '[') {
                throw new IllegalArgumentException("session line is nested");
            }
            throw new IllegalArgumentException("malformed session line");
        }

        private long number() {
            int start = index;
            boolean negative = line.charAt(index) == '-';
            if (negative) {
                index++;
            }
            if (index >= line.length() || line.charAt(index) < '0' || line.charAt(index) > '9') {
                throw new IllegalArgumentException("malformed session line");
            }
            if (line.charAt(index) == '0') {
                index++;
                if (negative || (index < line.length() && line.charAt(index) >= '0' && line.charAt(index) <= '9')) {
                    throw new IllegalArgumentException("session integer has a leading zero");
                }
            } else {
                while (index < line.length() && line.charAt(index) >= '0' && line.charAt(index) <= '9') {
                    index++;
                }
            }
            if (index < line.length()) {
                char next = line.charAt(index);
                if (next == '.' || next == 'e' || next == 'E') {
                    throw new IllegalArgumentException("session number is not an integer");
                }
            }
            try {
                return Long.parseLong(line.substring(start, index));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("session integer is out of range");
            }
        }
    }
}
