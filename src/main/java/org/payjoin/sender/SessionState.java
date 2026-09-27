package org.payjoin.sender;

import java.net.URI;
import java.time.Clock;
import java.util.Random;
import org.payjoin.sender.crypto.Secp256k1;
import org.payjoin.sender.ohttp.Ohttp;
import org.payjoin.sender.ohttp.OhttpKeys;
import org.payjoin.sender.uri.PayjoinUri;

/** Secrets and parameters restored from the log. The relay URL is not here. */
final class SessionState {
    final byte[] replySecret;
    final String originalPsbt;
    final byte[] payee;
    final String endpoint;
    final long expiry;
    final byte[] ohttpKey;
    final byte[] receiverCompressed;
    final boolean substitution;
    final Integer feeIndex;
    final Long feeSats;
    final Long minFee;
    final Persister persister;
    final Clock clock;
    final Random random;
    Ohttp.Context context;
    boolean closed;

    SessionState(
            byte[] replySecret,
            String originalPsbt,
            byte[] payee,
            String endpoint,
            long expiry,
            byte[] ohttpKey,
            byte[] receiverCompressed,
            boolean substitution,
            Integer feeIndex,
            Long feeSats,
            Long minFee,
            Persister persister,
            Clock clock,
            Random random) {
        this.replySecret = replySecret;
        this.originalPsbt = originalPsbt;
        this.payee = payee;
        this.endpoint = endpoint;
        this.expiry = expiry;
        this.ohttpKey = ohttpKey;
        this.receiverCompressed = receiverCompressed;
        this.substitution = substitution;
        this.feeIndex = feeIndex;
        this.feeSats = feeSats;
        this.minFee = minFee;
        this.persister = persister;
        this.clock = clock;
        this.random = random;
    }

    void requireOpen() {
        if (closed) {
            throw new SessionException("session is closed");
        }
    }

    void failIfExpired() {
        if (clock.instant().getEpochSecond() >= expiry) {
            abort();
            throw new SessionException("expired");
        }
    }

    void abort() {
        if (!closed) {
            persister.append(EventLog.closed("aborted", null));
            closed = true;
        }
    }

    String relayUrl(String relay) {
        if (relay == null || relay.isEmpty()) {
            throw new IllegalArgumentException("relay is required");
        }
        URI uri;
        try {
            uri = URI.create(relay);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("relay must be an absolute http URL", e);
        }
        String scheme = uri.getScheme();
        if (scheme == null
                || uri.getHost() == null
                || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
            throw new IllegalArgumentException("relay must be an absolute http URL");
        }
        String base = relay.endsWith("/") ? relay.substring(0, relay.length() - 1) : relay;
        int schemeEnd = endpoint.indexOf("://");
        int path = endpoint.indexOf('/', schemeEnd + 3);
        return base + "/" + endpoint.substring(0, path + 1);
    }

    String pollTarget() {
        int slash = endpoint.lastIndexOf('/');
        String id = PayjoinUri.shortIdOf(Secp256k1.compressedPublicKey(replySecret));
        return endpoint.substring(0, slash + 1) + id;
    }

    Ohttp.Request encapsulate(String method, String target, byte[] body) {
        return Ohttp.encapsulate(OhttpKeys.parse(ohttpKey), method, target, body, random);
    }

    byte[] receiverUncompressed() {
        return Secp256k1.uncompressed(receiverCompressed);
    }
}
