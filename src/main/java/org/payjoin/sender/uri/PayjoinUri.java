package org.payjoin.sender.uri;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * A BIP 21 URI whose {@code pj} parameter is a BIP 77 mailbox.
 * The formatted form uppercases the mailbox scheme and host and writes
 * fragment parameters in lexicographical order separated by {@code -}.
 */
public final class PayjoinUri {
    private final String address;
    private final Long amountSats;
    private final String amountText;
    private final boolean outputSubstitution;
    private final String scheme;
    private final String host;
    private final Integer port;
    private final ShortId shortId;
    private final long expirationUnix;
    private final int ohttpKeyId;
    private final byte[] ohttpGatewayKey;
    private final byte[] receiverKey;

    private PayjoinUri(
            String address,
            Long amountSats,
            String amountText,
            boolean outputSubstitution,
            String scheme,
            String host,
            Integer port,
            ShortId shortId,
            long expirationUnix,
            int ohttpKeyId,
            byte[] ohttpGatewayKey,
            byte[] receiverKey) {
        this.address = address;
        this.amountSats = amountSats;
        this.amountText = amountText;
        this.outputSubstitution = outputSubstitution;
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.shortId = shortId;
        this.expirationUnix = expirationUnix;
        this.ohttpKeyId = ohttpKeyId;
        this.ohttpGatewayKey = ohttpGatewayKey;
        this.receiverKey = receiverKey;
    }

    public static PayjoinUri parse(String uri) {
        if (uri == null || !uri.startsWith("bitcoin:")) {
            throw new UriParseException(UriParseException.Reason.INVALID_URI, "not a bitcoin URI");
        }
        String rest = uri.substring("bitcoin:".length());
        int queryAt = rest.indexOf('?');
        if (queryAt <= 0) {
            throw new UriParseException(UriParseException.Reason.INVALID_URI, "missing query");
        }
        String address = rest.substring(0, queryAt);
        Map<String, String> query = parseQuery(rest.substring(queryAt + 1));
        if (!query.containsKey("pj")) {
            throw new UriParseException(UriParseException.Reason.NOT_V2, "missing pj");
        }
        boolean substitution = true;
        if (query.containsKey("pjos")) {
            substitution = switch (query.get("pjos")) {
                case "0" -> false;
                case "1" -> true;
                default -> throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "bad pjos");
            };
        }
        Mailbox mailbox = parseMailbox(percentDecode(query.get("pj")));
        Long amount = null;
        String amountText = query.get("amount");
        if (amountText != null) {
            amount = parseAmount(amountText);
        }
        return new PayjoinUri(
                address,
                amount,
                amountText,
                substitution,
                mailbox.scheme,
                mailbox.host,
                mailbox.port,
                mailbox.shortId,
                mailbox.expirationUnix,
                mailbox.ohttpKeyId,
                mailbox.ohttpGatewayKey,
                mailbox.receiverKey);
    }

    public String address() {
        return address;
    }

    public Long amountSats() {
        return amountSats;
    }

    public boolean outputSubstitution() {
        return outputSubstitution;
    }

    public ShortId shortId() {
        return shortId;
    }

    public long expirationUnix() {
        return expirationUnix;
    }

    public int ohttpKeyId() {
        return ohttpKeyId;
    }

    public byte[] ohttpGatewayKey() {
        return ohttpGatewayKey.clone();
    }

    public byte[] receiverKey() {
        return receiverKey.clone();
    }

    @Override
    public String toString() {
        StringBuilder query = new StringBuilder();
        if (amountText != null) {
            query.append("amount=").append(amountText).append('&');
        }
        if (!outputSubstitution) {
            query.append("pjos=0&");
        }
        query.append("pj=").append(percentEncodeHash(mailbox()));
        return "bitcoin:" + address + "?" + query;
    }

    public String mailbox() {
        byte[] expiration = new byte[] {
            (byte) expirationUnix,
            (byte) (expirationUnix >>> 8),
            (byte) (expirationUnix >>> 16),
            (byte) (expirationUnix >>> 24)
        };
        byte[] oh = new byte[34];
        oh[0] = (byte) ohttpKeyId;
        System.arraycopy(ohttpGatewayKey, 0, oh, 1, 33);
        Map<String, String> params = new TreeMap<>();
        params.put("EX", Bech32.encode("EX", expiration));
        params.put("OH", Bech32.encode("OH", oh));
        params.put("RK", Bech32.encode("RK", receiverKey));
        return scheme.toUpperCase(Locale.ROOT)
                + "://"
                + host.toUpperCase(Locale.ROOT)
                + (port == null ? "" : ":" + port)
                + "/"
                + shortId
                + "#"
                + String.join("-", params.values());
    }

    private static Mailbox parseMailbox(String pj) {
        int hash = pj.indexOf('#');
        if (hash < 0) {
            throw new UriParseException(UriParseException.Reason.NOT_V2, "missing fragment");
        }
        String fragment = pj.substring(hash + 1);
        if (fragment.chars().anyMatch(c -> Character.isLowerCase(c))) {
            throw new UriParseException(UriParseException.Reason.LOWERCASE_FRAGMENT, "lowercase fragment");
        }
        if (fragment.indexOf('+') >= 0 && fragment.indexOf('-') >= 0) {
            throw new UriParseException(UriParseException.Reason.AMBIGUOUS_DELIMITER, "mixed fragment delimiters");
        }
        for (int i = 0; i < fragment.length(); i++) {
            char c = fragment.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '-' || c == '+';
            if (!ok) {
                throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "invalid fragment character");
            }
        }
        char delimiter = fragment.indexOf('+') >= 0 ? '+' : '-';
        String before = pj.substring(0, hash);
        int schemeEnd = before.indexOf("://");
        if (schemeEnd <= 0) {
            throw new UriParseException(UriParseException.Reason.INVALID_URI, "missing mailbox scheme");
        }
        String scheme = before.substring(0, schemeEnd);
        if (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http")) {
            throw new UriParseException(UriParseException.Reason.INVALID_URI, "unsupported mailbox scheme");
        }
        String afterScheme = before.substring(schemeEnd + 3);
        int slash = afterScheme.indexOf('/');
        if (slash <= 0 || slash == afterScheme.length() - 1) {
            throw new UriParseException(UriParseException.Reason.NOT_V2, "missing short id");
        }
        String authority = afterScheme.substring(0, slash);
        String path = afterScheme.substring(slash + 1);
        if (path.indexOf('/') >= 0) {
            throw new UriParseException(UriParseException.Reason.NOT_V2, "unexpected mailbox path");
        }
        Integer port = null;
        String host = authority;
        int colon = authority.lastIndexOf(':');
        if (colon >= 0 && authority.indexOf(']') < 0) {
            host = authority.substring(0, colon);
            try {
                port = Integer.valueOf(authority.substring(colon + 1));
            } catch (NumberFormatException e) {
                throw new UriParseException(UriParseException.Reason.INVALID_URI, "bad port");
            }
        }
        Map<String, String> params = new LinkedHashMap<>();
        for (String part : fragment.split(java.util.regex.Pattern.quote(String.valueOf(delimiter)), -1)) {
            if (part.isEmpty()) {
                continue;
            }
            int sep = part.lastIndexOf('1');
            if (sep <= 0) {
                throw new UriParseException(UriParseException.Reason.INVALID_BECH32, "invalid fragment parameter");
            }
            String key = part.substring(0, sep);
            if (params.containsKey(key)) {
                throw new UriParseException(UriParseException.Reason.DUPLICATE_PARAMETER, "duplicate " + key);
            }
            params.put(key, part);
        }
        if (!params.containsKey("EX") || !params.containsKey("OH") || !params.containsKey("RK")) {
            throw new UriParseException(UriParseException.Reason.NOT_V2, "missing session parameter");
        }
        byte[] expiration = decodeParam("EX", params.get("EX"), 4);
        byte[] oh = decodeParam("OH", params.get("OH"), 34);
        byte[] receiver = decodeParam("RK", params.get("RK"), 33);
        if (!isCompressedKey(receiver) || !isCompressedKey(Arrays.copyOfRange(oh, 1, 34))) {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "invalid public key");
        }
        long unix = (expiration[0] & 0xffL)
                | ((expiration[1] & 0xffL) << 8)
                | ((expiration[2] & 0xffL) << 16)
                | ((expiration[3] & 0xffL) << 24);
        return new Mailbox(
                scheme,
                host,
                port,
                ShortId.parse(path),
                unix,
                oh[0] & 0xff,
                Arrays.copyOfRange(oh, 1, 34),
                receiver);
    }

    private static byte[] decodeParam(String hrp, String encoded, int length) {
        Bech32.Decoded decoded = Bech32.decode(encoded);
        if (!decoded.hrp().equals(hrp) || decoded.data().length != length) {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "bad " + hrp);
        }
        return decoded.data();
    }

    private static boolean isCompressedKey(byte[] key) {
        return key.length == 33 && (key[0] == 0x02 || key[0] == 0x03);
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query.isEmpty()) {
            return params;
        }
        for (String part : query.split("&", -1)) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                throw new UriParseException(UriParseException.Reason.INVALID_URI, "bad query");
            }
            String key = part.substring(0, eq);
            if (params.containsKey(key) && (key.equals("pj") || key.equals("pjos"))) {
                throw new UriParseException(UriParseException.Reason.DUPLICATE_PARAMETER, "duplicate " + key);
            }
            params.put(key, part.substring(eq + 1));
        }
        return params;
    }

    private static long parseAmount(String text) {
        if (text.isEmpty() || text.charAt(0) == '-' || text.charAt(0) == '+') {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "bad amount");
        }
        String whole;
        String fraction = "";
        int dot = text.indexOf('.');
        if (dot < 0) {
            whole = text;
        } else if (text.indexOf('.', dot + 1) >= 0) {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "bad amount");
        } else {
            whole = text.substring(0, dot);
            fraction = text.substring(dot + 1);
        }
        if (fraction.length() > 8 || !digits(whole) || !digits(fraction)) {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "bad amount");
        }
        if (whole.isEmpty()) {
            whole = "0";
        }
        while (fraction.length() < 8) {
            fraction = fraction + "0";
        }
        try {
            return Math.addExact(Math.multiplyExact(Long.parseLong(whole), 100_000_000L), Long.parseLong(fraction));
        } catch (NumberFormatException | ArithmeticException e) {
            throw new UriParseException(UriParseException.Reason.INVALID_PARAMETER, "bad amount");
        }
    }

    private static boolean digits(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static String percentDecode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '%') {
                out.append(c);
                continue;
            }
            if (i + 2 >= value.length()) {
                throw new UriParseException(UriParseException.Reason.INVALID_URI, "bad percent encoding");
            }
            int decoded;
            try {
                decoded = Integer.parseInt(value.substring(i + 1, i + 3), 16);
            } catch (NumberFormatException e) {
                throw new UriParseException(UriParseException.Reason.INVALID_URI, "bad percent encoding");
            }
            out.append((char) decoded);
            i += 2;
        }
        return out.toString();
    }

    private static String percentEncodeHash(String value) {
        return value.replace("#", "%23");
    }

    private record Mailbox(
            String scheme,
            String host,
            Integer port,
            ShortId shortId,
            long expirationUnix,
            int ohttpKeyId,
            byte[] ohttpGatewayKey,
            byte[] receiverKey) {}
}
