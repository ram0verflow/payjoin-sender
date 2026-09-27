package dev.ramoverflow.payjoin.sender;

/** The receiver or directory sent a response that does not follow the session. */
public final class CounterpartyException extends SessionException {
    /** Creates an exception with {@code message}. */
    public CounterpartyException(String message) {
        super(message);
    }

    /** Creates an exception with {@code message} and {@code cause}. */
    public CounterpartyException(String message, Throwable cause) {
        super(message, cause);
    }
}
