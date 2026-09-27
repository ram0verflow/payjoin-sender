package org.payjoin.sender;

import java.util.Base64;
import org.payjoin.sender.crypto.Secp256k1;
import org.payjoin.sender.ohttp.Ohttp;

/** The Original PSBT is posted. Poll until a proposal arrives or the session expires. */
public final class Poll implements Session {
    private final SessionState state;
    private boolean spent;

    Poll(SessionState state) {
        this.state = state;
    }

    /** A new encapsulated GET. The inner payload is empty. The outer method is still POST. */
    public Request request(String relay) {
        state.requireOpen();
        if (spent) {
            throw new SessionException("step already completed");
        }
        state.failIfExpired();
        byte[] message = Messages.encryptA(
                new byte[0],
                Secp256k1.compressedPublicKey(state.replySecret),
                state.receiverUncompressed(),
                state.random);
        Ohttp.Request encapsulated = state.encapsulate("GET", state.pollTarget(), message);
        state.context = encapsulated.context();
        return new Request(state.relayUrl(relay), "POST", encapsulated.encapsulated());
    }

    /**
     * A directory status of 202 returns this same step while the session has not expired.
     * A proposal closes the session. It is not ready to sign.
     */
    public Session resume(int status, byte[] body) {
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
        if (reply.status() == 202) {
            if (state.clock.instant().getEpochSecond() >= state.expiry) {
                state.abort();
                spent = true;
                throw new SessionException("expired");
            }
            return this;
        }
        if (reply.status() != 200) {
            throw new CounterpartyException("directory status " + reply.status());
        }
        try {
            byte[] plaintext = Messages.decryptB(reply.body(), state.replySecret, state.receiverUncompressed());
            byte[] psbt = PsbtBytes.proposal(plaintext);
            String encoded = Base64.getEncoder().encodeToString(psbt);
            state.persister.append(EventLog.closed("success", encoded));
            state.closed = true;
            spent = true;
            return new Proposal(encoded);
        } catch (RuntimeException e) {
            state.abort();
            spent = true;
            if (e instanceof SessionException) {
                throw e;
            }
            throw new CounterpartyException("proposal rejected", e);
        }
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

    String pollTarget() {
        return state.pollTarget();
    }
}
