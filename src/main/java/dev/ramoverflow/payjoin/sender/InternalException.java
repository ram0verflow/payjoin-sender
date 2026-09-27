package dev.ramoverflow.payjoin.sender;

/** A session invariant failed. This is a bug in the library, not in the counterparty. */
public final class InternalException extends SessionException {
    /** Creates an exception with {@code message}. */
    public InternalException(String message) {
        super(message);
    }
}
