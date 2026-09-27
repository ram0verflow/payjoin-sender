package org.payjoin.sender;

/** The receiver or directory sent a response that does not follow the session. */
public final class CounterpartyException extends SessionException {
    public CounterpartyException(String message) {
        super(message);
    }

    public CounterpartyException(String message, Throwable cause) {
        super(message, cause);
    }
}
