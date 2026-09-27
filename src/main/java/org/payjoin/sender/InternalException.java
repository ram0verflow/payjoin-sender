package org.payjoin.sender;

/** A session invariant failed. This is a bug in the library, not in the counterparty. */
public final class InternalException extends SessionException {
    public InternalException(String message) {
        super(message);
    }
}
