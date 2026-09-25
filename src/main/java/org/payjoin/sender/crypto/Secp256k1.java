package org.payjoin.sender.crypto;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/** Compressed and uncompressed secp256k1 keys, and ECDH. */
public final class Secp256k1 {
    static final X9ECParameters PARAMS = CustomNamedCurves.getByName("secp256k1");
    static final ECCurve CURVE = PARAMS.getCurve();
    static final BigInteger FIELD = CURVE.getField().getCharacteristic();
    private static final BigInteger ORDER = PARAMS.getN();
    private static final ECPoint GENERATOR = PARAMS.getG();

    private Secp256k1() {}

    public static byte[] publicKey(byte[] secretKey) {
        return point(secretKey).getEncoded(false);
    }

    public static byte[] compressedPublicKey(byte[] secretKey) {
        return point(secretKey).getEncoded(true);
    }

    /** Accepts a compressed or uncompressed encoding and returns the 65-byte form. */
    public static byte[] uncompressed(byte[] encoded) {
        return decodePoint(encoded).getEncoded(false);
    }

    /** 32-byte big-endian x coordinate of secret * public. */
    public static byte[] diffieHellman(byte[] secretKey, byte[] publicKey) {
        ECPoint shared = decodePoint(publicKey).multiply(scalar(secretKey)).normalize();
        return pad32(shared.getAffineXCoord().toBigInteger());
    }

    static ECPoint point(byte[] secretKey) {
        return GENERATOR.multiply(scalar(secretKey)).normalize();
    }

    static ECPoint decodePoint(byte[] encoded) {
        try {
            ECPoint point = CURVE.decodePoint(encoded);
            if (!point.isValid()) {
                throw new IllegalArgumentException("public key is not on the curve");
            }
            return point;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("invalid public key", e);
        }
    }

    static BigInteger scalar(byte[] secretKey) {
        if (secretKey.length != 32) {
            throw new IllegalArgumentException("secret key must be 32 bytes");
        }
        BigInteger scalar = new BigInteger(1, secretKey);
        if (scalar.signum() == 0 || scalar.compareTo(ORDER) >= 0) {
            throw new IllegalArgumentException("secret key is out of range");
        }
        return scalar;
    }

    static byte[] pad32(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        if (raw.length == 33 && raw[0] == 0) {
            return Arrays.copyOfRange(raw, 1, 33);
        }
        byte[] padded = new byte[32];
        System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
        return padded;
    }
}
