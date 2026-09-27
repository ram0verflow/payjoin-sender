package org.payjoin.sender;

/**
 * The receiver's proposal PSBT, base64-encoded.
 * The sender checklist has passed. Wallet metadata from the original PSBT
 * is not copied back into this string.
 */
public final class Proposal implements Session {
    private final String psbt;

    Proposal(String psbt) {
        this.psbt = psbt;
    }

    public String psbt() {
        return psbt;
    }
}
