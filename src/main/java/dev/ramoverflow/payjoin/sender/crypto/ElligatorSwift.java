package dev.ramoverflow.payjoin.sender.crypto;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * BIP 324 ElligatorSwift encoding of secp256k1 points. Decode follows the
 * secp256k1 specialization of the SwiftEC map. Encode searches a random
 * (u, c) pair and flips the sign of t so it matches the y coordinate.
 */
public final class ElligatorSwift {
    private static final BigInteger P = Secp256k1.FIELD;
    private static final BigInteger B = BigInteger.valueOf(7);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger SQRT_NEG_3 = sqrt(P.subtract(THREE));

    private ElligatorSwift() {}

    /** Encodes an uncompressed secp256k1 point as 64 bytes. */
    public static byte[] encode(byte[] publicKey, Random random) {
        var point = Secp256k1.decodePoint(publicKey);
        BigInteger x = point.getAffineXCoord().toBigInteger();
        BigInteger y = point.getAffineYCoord().toBigInteger();
        byte[] entropy = new byte[32];
        for (int attempt = 0; attempt < 128; attempt++) {
            random.nextBytes(entropy);
            BigInteger u = new BigInteger(1, entropy).mod(P);
            int c = random.nextInt(8);
            BigInteger t = inverse(c, u, x);
            if (t == null) {
                continue;
            }
            if (t.testBit(0) != y.testBit(0)) {
                t = t.negate().mod(P);
            }
            if (t.signum() == 0) {
                continue;
            }
            byte[] encoded = new byte[64];
            System.arraycopy(Secp256k1.pad32(u), 0, encoded, 0, 32);
            System.arraycopy(Secp256k1.pad32(t), 0, encoded, 32, 32);
            if (Arrays.equals(decode(encoded), point.getEncoded(false))) {
                return encoded;
            }
        }
        throw new IllegalStateException("ElligatorSwift encode failed");
    }

    /** Decodes 64 bytes to an uncompressed secp256k1 point. */
    public static byte[] decode(byte[] encoded) {
        if (encoded.length != 64) {
            throw new IllegalArgumentException("ElligatorSwift encoding must be 64 bytes");
        }
        BigInteger u = new BigInteger(1, Arrays.copyOfRange(encoded, 0, 32)).mod(P);
        BigInteger t = new BigInteger(1, Arrays.copyOfRange(encoded, 32, 64)).mod(P);
        BigInteger u1 = u.signum() == 0 ? BigInteger.ONE : u;
        BigInteger t1 = t.signum() == 0 ? BigInteger.ONE : t;
        BigInteger t2 = g(u1).add(t1.modPow(TWO, P)).mod(P).signum() == 0 ? t1.multiply(TWO).mod(P) : t1;
        BigInteger xNumerator = u1.modPow(THREE, P).add(B).subtract(t2.modPow(TWO, P)).mod(P);
        BigInteger bigX = xNumerator.multiply(inv(t2.multiply(TWO))).mod(P);
        BigInteger bigY = bigX.add(t2).multiply(inv(u1.multiply(SQRT_NEG_3))).mod(P);
        BigInteger x = firstOnCurve(
                u1.add(FOUR.multiply(bigY.modPow(TWO, P))).mod(P),
                bigX.negate().multiply(inv(TWO.multiply(bigY))).subtract(u1.multiply(inv(TWO))).mod(P),
                bigX.multiply(inv(TWO.multiply(bigY))).subtract(u1.multiply(inv(TWO))).mod(P));
        BigInteger y = sqrt(g(x));
        if (y.testBit(0) != t.testBit(0)) {
            y = y.negate().mod(P);
        }
        byte[] raw = new byte[65];
        raw[0] = 0x04;
        System.arraycopy(Secp256k1.pad32(x), 0, raw, 1, 32);
        System.arraycopy(Secp256k1.pad32(y), 0, raw, 33, 32);
        return raw;
    }

    private static BigInteger inverse(int c, BigInteger u, BigInteger x) {
        if (u.signum() == 0) {
            return null;
        }
        BigInteger s;
        BigInteger v;
        if (c == 0 || c == 1 || c == 4 || c == 5) {
            if (isSquare(g(u.negate().subtract(x).mod(P)))) {
                return null;
            }
            BigInteger denominator = u.modPow(TWO, P).add(u.multiply(x)).add(x.modPow(TWO, P)).mod(P);
            s = g(u).negate().multiply(inv(denominator)).mod(P);
            v = x;
        } else {
            s = x.subtract(u).mod(P);
            BigInteger radicand = s.negate()
                    .multiply(FOUR.multiply(g(u)).add(THREE.multiply(s).multiply(u.modPow(TWO, P))))
                    .mod(P);
            BigInteger r = sqrtOrNull(radicand);
            if (r == null || ((c == 3 || c == 7) && r.signum() == 0) || s.signum() == 0) {
                return null;
            }
            v = r.multiply(inv(s)).subtract(u).multiply(inv(TWO)).mod(P);
        }
        BigInteger w = sqrtOrNull(s);
        if (w == null) {
            return null;
        }
        BigInteger minus = SQRT_NEG_3.negate();
        return switch (c) {
            case 0, 2 -> w.multiply(SQRT_NEG_3.subtract(BigInteger.ONE).multiply(inv(TWO)).multiply(u).subtract(v)).mod(P);
            case 1, 3 -> w.multiply(SQRT_NEG_3.add(BigInteger.ONE).multiply(inv(TWO)).multiply(u).add(v)).mod(P);
            case 4, 6 -> w.multiply(minus.add(BigInteger.ONE).multiply(inv(TWO)).multiply(u).add(v)).mod(P);
            default -> w.multiply(minus.subtract(BigInteger.ONE).multiply(inv(TWO)).multiply(u).subtract(v)).mod(P);
        };
    }

    private static BigInteger firstOnCurve(BigInteger... candidates) {
        for (BigInteger candidate : candidates) {
            if (isSquare(g(candidate))) {
                return candidate;
            }
        }
        throw new IllegalStateException("ElligatorSwift decode left the curve");
    }

    private static BigInteger g(BigInteger x) {
        return x.modPow(THREE, P).add(B).mod(P);
    }

    private static boolean isSquare(BigInteger value) {
        return sqrtOrNull(value) != null;
    }

    private static BigInteger sqrtOrNull(BigInteger value) {
        BigInteger root = sqrt(value);
        return root.modPow(TWO, P).equals(value) ? root : null;
    }

    private static BigInteger sqrt(BigInteger value) {
        return value.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
    }

    private static BigInteger inv(BigInteger value) {
        return value.modInverse(P);
    }
}
