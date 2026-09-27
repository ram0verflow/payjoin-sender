package org.payjoin.sender;

/** A session could not continue. Typed causes come later. */
public class SessionException extends IllegalStateException {
    public SessionException(String message) {
        super(message);
    }

    public SessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
