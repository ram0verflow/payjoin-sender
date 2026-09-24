package org.payjoin.sender.uri;

/** A BIP 21 Payjoin URI or one of its session parameters could not be parsed. */
public final class UriParseException extends IllegalArgumentException {
    public enum Reason {
        INVALID_URI,
        NOT_V2,
        LOWERCASE_FRAGMENT,
        AMBIGUOUS_DELIMITER,
        INVALID_BECH32,
        INVALID_PARAMETER,
        DUPLICATE_PARAMETER
    }

    private final Reason reason;

    UriParseException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
