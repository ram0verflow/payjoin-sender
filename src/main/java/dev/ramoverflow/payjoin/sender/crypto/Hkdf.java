package dev.ramoverflow.payjoin.sender.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/** HKDF-SHA256 as specified in RFC 5869. */
public final class Hkdf {
    private Hkdf() {}

    /** HKDF-Extract. An empty salt uses a string of 32 zero bytes. */
    public static byte[] extract(byte[] salt, byte[] inputKeyingMaterial) {
        byte[] actualSalt = salt == null || salt.length == 0 ? new byte[32] : salt;
        HMac mac = new HMac(new SHA256Digest());
        mac.init(new KeyParameter(actualSalt));
        mac.update(inputKeyingMaterial, 0, inputKeyingMaterial.length);
        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);
        return output;
    }

    /** HKDF-Expand to {@code length} bytes. */
    public static byte[] expand(byte[] pseudorandomKey, byte[] info, int length) {
        HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(HKDFParameters.skipExtractParameters(pseudorandomKey, info));
        byte[] output = new byte[length];
        generator.generateBytes(output, 0, length);
        return output;
    }
}
