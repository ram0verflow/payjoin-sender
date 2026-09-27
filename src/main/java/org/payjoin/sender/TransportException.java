package org.payjoin.sender;

/** The relay response was missing, the wrong size, or could not be opened. */
public final class TransportException extends SessionException {
    public TransportException(String message) {
        super(message);
    }

    public TransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
