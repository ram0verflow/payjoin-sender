package org.payjoin.sender;

/**
 * The receiver's proposal PSBT, base64-encoded.
 * The BIP 78 sender checklist has not run, so this PSBT is not ready to sign.
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
