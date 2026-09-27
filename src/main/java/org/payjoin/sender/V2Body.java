package org.payjoin.sender;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Original PSBT body: base64, a newline, then the v2 query string. */
final class V2Body {
    static final int MAX_BODY = 7055;

    private V2Body() {}

    static byte[] encode(String psbtBase64, boolean substitution, Integer feeIndex, Long feeSats, Long minFee) {
        if (psbtBase64 == null || psbtBase64.isEmpty()) {
            throw new IllegalArgumentException("original psbt is required");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(psbtBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("original psbt is not base64", e);
        }
        if (PsbtBytes.end(raw) != raw.length) {
            throw new IllegalArgumentException("original psbt has trailing bytes");
        }
        String body = psbtBase64 + "\n" + query(substitution, feeIndex, feeSats, minFee);
        byte[] encoded = body.getBytes(StandardCharsets.US_ASCII);
        if (encoded.length > MAX_BODY) {
            throw new IllegalArgumentException("original psbt is too large");
        }
        return encoded;
    }

    static String query(boolean substitution, Integer feeIndex, Long feeSats, Long minFee) {
        StringBuilder query = new StringBuilder("v=2");
        if (!substitution) {
            query.append("&disableoutputsubstitution=true");
        }
        if (feeIndex != null) {
            query.append("&additionalfeeoutputindex=").append(feeIndex);
            query.append("&maxadditionalfeecontribution=").append(feeSats);
        }
        if (minFee != null && minFee > 0) {
            query.append("&minfeerate=").append(minFee);
        }
        return query.toString();
    }
}
