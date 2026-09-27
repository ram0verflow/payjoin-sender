package org.payjoin.sender;

/**
 * BIP 78 sender parameters for one session.
 * Fee amounts are satoshis. The minimum fee rate is satoshis per virtual byte.
 * A null fee pair contributes nothing. A null or zero minimum fee rate is omitted.
 */
public final class Options {
    private final Long maxFeeSats;
    private final Integer feeOutputIndex;
    private final Long minFeeSatPerVbyte;
    private final boolean disableOutputSubstitution;

    public Options(
            Long maxFeeSats,
            Integer feeOutputIndex,
            Long minFeeSatPerVbyte,
            boolean disableOutputSubstitution) {
        if ((maxFeeSats == null) != (feeOutputIndex == null)) {
            throw new IllegalArgumentException("fee contribution needs both an amount and an output index");
        }
        if (maxFeeSats != null && (maxFeeSats < 0 || feeOutputIndex < 0)) {
            throw new IllegalArgumentException("fee contribution must be non-negative");
        }
        if (minFeeSatPerVbyte != null && minFeeSatPerVbyte < 0) {
            throw new IllegalArgumentException("min fee rate must be non-negative");
        }
        this.maxFeeSats = maxFeeSats;
        this.feeOutputIndex = feeOutputIndex;
        this.minFeeSatPerVbyte = minFeeSatPerVbyte == null || minFeeSatPerVbyte == 0 ? null : minFeeSatPerVbyte;
        this.disableOutputSubstitution = disableOutputSubstitution;
    }

    public static Options none() {
        return new Options(null, null, null, false);
    }

    Long maxFeeSats() {
        return maxFeeSats;
    }

    Integer feeOutputIndex() {
        return feeOutputIndex;
    }

    Long minFeeSatPerVbyte() {
        return minFeeSatPerVbyte;
    }

    boolean disableOutputSubstitution() {
        return disableOutputSubstitution;
    }
}
