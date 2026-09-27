package dev.ramoverflow.payjoin.sender;

import java.util.List;

/**
 * Append-only session log. Each string is one JSON object and does not
 * include the newline. The log contains the reply key and the Original
 * PSBT. The caller protects it at rest. This library does not encrypt it.
 * OHTTP ciphertext, the response context, and the relay URL are not stored.
 */
public interface Persister {
    /** Appends one log line. The string does not include a newline. */
    void append(String line);

    /** Every stored line, in order, without newlines. */
    List<String> load();
}
