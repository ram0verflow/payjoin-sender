package dev.ramoverflow.payjoin.sender;

/** A session could not continue. */
public class SessionException extends IllegalStateException {
    /** Creates an exception with {@code message}. */
    public SessionException(String message) {
        super(message);
    }

    /** Creates an exception with {@code message} and {@code cause}. */
    public SessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
