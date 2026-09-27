package org.payjoin.sender;

import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import org.payjoin.sender.crypto.Secp256k1;
import org.payjoin.sender.uri.PayjoinUri;

/**
 * Starts a BIP 77 sender session and restores one from its log.
 * {@link #resume(Persister, Clock, Random)} after a crash that happened once the POST
 * was sent, and before that response was resumed, returns a post step. The next
 * request is a new ciphertext. Resuming a posted session returns a poll step.
 */
public final class Sender {
    private Sender() {}

    public static Post start(
            String uri, String originalPsbtBase64, Options options, Clock clock, Random random, Persister persister) {
        Objects.requireNonNull(options, "options");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        Objects.requireNonNull(persister, "persister");
        PayjoinUri parsed = PayjoinUri.parse(uri);
        byte[] payee = AddressScript.script(parsed.address());
        boolean substitution = parsed.outputSubstitution() && !options.disableOutputSubstitution();
        V2Body.encode(originalPsbtBase64, substitution, options.feeOutputIndex(), options.maxFeeSats(), options.minFeeSatPerVbyte());
        Checklist.vetOriginal(originalPsbtBase64, payee, parsed.amountSats());
        byte[] reply = replySecret(random);
        byte[] ohttp = new byte[34];
        ohttp[0] = (byte) parsed.ohttpKeyId();
        System.arraycopy(parsed.ohttpGatewayKey(), 0, ohttp, 1, 33);
        EventLog.Event created = new EventLog.Event("created");
        created.reply = Hex.encode(reply);
        created.psbt = originalPsbtBase64;
        created.payee = Hex.encode(payee);
        created.endpoint = endpoint(parsed);
        created.expiry = parsed.expirationUnix();
        created.ohttp = Hex.encode(ohttp);
        created.receiver = Hex.encode(parsed.receiverKey());
        created.substitution = substitution;
        created.feeIndex = options.feeOutputIndex();
        created.feeSats = options.maxFeeSats();
        created.minFee = options.minFeeSatPerVbyte();
        persister.append(EventLog.created(created));
        return new Post(state(created, persister, clock, random));
    }

    public static Session resume(Persister persister, Clock clock, Random random) {
        Objects.requireNonNull(persister, "persister");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        List<String> lines = persister.load();
        if (lines.isEmpty()) {
            throw new SessionException("empty session");
        }
        EventLog.Event created = event(lines.get(0));
        if (!created.type.equals("created")) {
            throw new SessionException("session does not start with created");
        }
        SessionState state = state(created, persister, clock, random);
        int index = 1;
        boolean posted = false;
        if (index < lines.size() && event(lines.get(index)).type.equals("posted")) {
            posted = true;
            index++;
        }
        if (index < lines.size()) {
            EventLog.Event next = event(lines.get(index));
            if (next.type.equals("cancelled")) {
                throw new SessionException("session cancelled");
            }
            if (!next.type.equals("closed")) {
                throw new SessionException("unexpected session event");
            }
            index++;
            if (index != lines.size()) {
                throw new SessionException("unexpected session event");
            }
            state.closed = true;
            if ("aborted".equals(next.outcome)) {
                throw new SessionException("session aborted");
            }
            if (!posted) {
                throw new SessionException("session closed before it was posted");
            }
            Checklist.accept(
                    state.originalPsbt,
                    java.util.Base64.getDecoder().decode(next.proposal),
                    state.payee,
                    state.substitution,
                    state.feeIndex,
                    state.feeSats,
                    state.minFee);
            return new Proposal(next.proposal);
        }
        return posted ? new Poll(state) : new Post(state);
    }

    private static SessionState state(EventLog.Event created, Persister persister, Clock clock, Random random) {
        byte[] reply = Hex.decode(created.reply, 32);
        byte[] receiver = Hex.decode(created.receiver, 33);
        byte[] ohttp = Hex.decode(created.ohttp, 34);
        try {
            Secp256k1.publicKey(reply);
            Secp256k1.uncompressed(receiver);
        } catch (IllegalArgumentException e) {
            throw new SessionException("session key is invalid", e);
        }
        return new SessionState(
                reply,
                created.psbt,
                Hex.decode(created.payee),
                created.endpoint,
                created.expiry,
                ohttp,
                receiver,
                created.substitution,
                created.feeIndex,
                created.feeSats,
                created.minFee,
                persister,
                clock,
                random);
    }

    private static EventLog.Event event(String line) {
        try {
            return EventLog.parse(line);
        } catch (IllegalArgumentException e) {
            throw new SessionException("bad session log", e);
        }
    }

    private static byte[] replySecret(Random random) {
        byte[] secret = new byte[32];
        for (int attempt = 0; attempt < 64; attempt++) {
            random.nextBytes(secret);
            try {
                Secp256k1.publicKey(secret);
                return secret.clone();
            } catch (IllegalArgumentException ignored) {
                // Draw again. A uniform 32-byte string is occasionally out of range.
            }
        }
        throw new IllegalStateException("could not draw a reply key");
    }

    private static String endpoint(PayjoinUri uri) {
        String mailbox = uri.mailbox();
        int hash = mailbox.indexOf('#');
        String url = mailbox.substring(0, hash);
        int schemeEnd = url.indexOf("://");
        int path = url.indexOf('/', schemeEnd + 3);
        String scheme = url.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
        String authority = url.substring(schemeEnd + 3, path).toLowerCase(Locale.ROOT);
        return scheme + "://" + authority + url.substring(path);
    }
}
