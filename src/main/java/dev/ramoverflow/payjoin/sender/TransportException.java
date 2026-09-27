package dev.ramoverflow.payjoin.sender;

/** The relay response was missing, the wrong size, or could not be opened. */
public final class TransportException extends SessionException {
    /** Creates an exception with {@code message}. */
    public TransportException(String message) {
        super(message);
    }

    /** Creates an exception with {@code message} and {@code cause}. */
    public TransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
