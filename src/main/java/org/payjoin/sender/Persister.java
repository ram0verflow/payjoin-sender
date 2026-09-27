package org.payjoin.sender;

import java.util.List;

/**
 * Append-only session log. Each string is one JSON object and does not
 * include the newline. The log contains the reply key and the Original
 * PSBT. The caller protects it at rest. This library does not encrypt it.
 * OHTTP ciphertext, the response context, and the relay URL are not stored.
 */
public interface Persister {
    void append(String line);

    List<String> load();
}
