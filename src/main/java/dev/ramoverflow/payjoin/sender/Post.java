package dev.ramoverflow.payjoin.sender;

import dev.ramoverflow.payjoin.sender.crypto.Secp256k1;
import dev.ramoverflow.payjoin.sender.ohttp.Ohttp;

/** The session has a reply key and still needs to POST the Original PSBT. */
public final class Post implements Session {
    private final SessionState state;
    private boolean spent;

    Post(SessionState state) {
        this.state = state;
    }

    /**
     * A new encapsulated POST. Calling this again drops the previous unsent ciphertext.
     * A crash after the caller sends it and before {@link #resume} does not retry that ciphertext.
     */
    public Request request(String relay) {
        state.requireOpen();
        if (spent) {
            throw new SessionException("step already completed");
        }
        state.failIfExpired();
        byte[] body = V2Body.encode(
                state.originalPsbt, state.substitution, state.feeIndex, state.feeSats, state.minFee);
        byte[] message = Messages.encryptA(
                body,
                Secp256k1.compressedPublicKey(state.replySecret),
                state.receiverUncompressed(),
                state.random);
        Ohttp.Request encapsulated = state.encapsulate("POST", state.endpoint, message);
        state.context = encapsulated.context();
        return new Request(state.relayUrl(relay), "POST", encapsulated.encapsulated());
    }

    /** Decapsulates the relay response. A directory status of 200 records {@code posted}. */
    public Poll resume(int status, byte[] body) {
        state.requireOpen();
        if (spent) {
            throw new SessionException("step already completed");
        }
        if (state.context == null) {
            throw new SessionException("call request before resume");
        }
        if (status != 200) {
            throw new TransportException("relay status " + status);
        }
        Ohttp.Reply reply = open(body);
        if (reply.status() != 200) {
            throw new CounterpartyException("directory status " + reply.status());
        }
        state.persister.append(EventLog.posted());
        spent = true;
        return new Poll(state);
    }

    private Ohttp.Reply open(byte[] body) {
        try {
            Ohttp.Reply reply = Ohttp.decapsulate(state.context, body);
            state.context = null;
            return reply;
        } catch (RuntimeException e) {
            state.context = null;
            throw new TransportException("directory response failed to open", e);
        }
    }

    Ohttp.Context context() {
        return state.context;
    }
}
