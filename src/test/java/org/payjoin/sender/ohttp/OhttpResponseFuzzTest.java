package org.payjoin.sender.ohttp;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Random;
import org.junit.jupiter.api.Tag;
import org.payjoin.sender.FuzzKeys;
import org.payjoin.sender.SecretText;
import org.payjoin.sender.crypto.Secp256k1;

/** Hostile bytes for an OHTTP response. */
@Tag("fuzz")
class OhttpResponseFuzzTest {
    private static final byte[] GATEWAY = FuzzKeys.secret(7);
    private static final Ohttp.Context CONTEXT = context();

    @FuzzTest(maxDuration = "30s")
    void response(byte[] data) {
        try {
            Ohttp.decapsulate(CONTEXT, data);
        } catch (IllegalArgumentException e) {
            SecretText.refuse(e, data, FuzzKeys.reply(), GATEWAY, CONTEXT.exporterSecret());
        }
    }

    private static Ohttp.Context context() {
        byte[] config = new byte[34];
        config[0] = 1;
        System.arraycopy(Secp256k1.compressedPublicKey(GATEWAY), 0, config, 1, 33);
        return Ohttp.encapsulate(OhttpKeys.parse(config), "POST", "https://payjo.in/abc", new byte[0], new Random(1))
                .context();
    }
}
