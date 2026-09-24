package org.payjoin.sender.crypto;

import java.math.BigInteger;

/**
 * HPKE with DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305.
 * The KEM id is {@code 0x0016}. Bouncy Castle's HPKE KEM type cannot be
 * subclassed from this package, so the RFC 9180 key schedule lives here.
 */
public final class Hpke {
    public static final short KEM_SECP256K1 = 0x0016;
    private static final byte[] KEM_SUITE = new byte[] {'K', 'E', 'M', 0x00, 0x16};
    private static final byte[] HPKE_SUITE = new byte[] {'H', 'P', 'K', 'E', 0x00, 0x16, 0x00, 0x01, 0x00, 0x03};
    private static final byte MODE_BASE = 0x00;
    private static final byte MODE_AUTH = 0x02;
    private static final BigInteger ORDER = Secp256k1.PARAMS.getN();

    private Hpke() {}

    public record Context(byte[] encapsulatedKey, byte[] key, byte[] baseNonce, byte[] exporterSecret) {}

    public static Context setupBase(byte[] ikmE, byte[] receiverPublicKey, byte[] info) {
        byte[] secretKey = deriveSecretKey(ikmE);
        byte[] encapsulated = Secp256k1.publicKey(secretKey);
        byte[] dh = Secp256k1.diffieHellman(secretKey, receiverPublicKey);
        byte[] shared = extractAndExpand(dh, concat(encapsulated, receiverPublicKey));
        return schedule(MODE_BASE, shared, info, encapsulated);
    }

    public static Context setupAuth(
            byte[] ikmE, byte[] senderSecretKey, byte[] receiverPublicKey, byte[] info) {
        byte[] secretKey = deriveSecretKey(ikmE);
        byte[] encapsulated = Secp256k1.publicKey(secretKey);
        byte[] senderPublic = Secp256k1.publicKey(senderSecretKey);
        byte[] dh = concat(
                Secp256k1.diffieHellman(secretKey, receiverPublicKey),
                Secp256k1.diffieHellman(senderSecretKey, receiverPublicKey));
        byte[] shared = extractAndExpand(dh, concat(encapsulated, receiverPublicKey, senderPublic));
        return schedule(MODE_AUTH, shared, info, encapsulated);
    }

    public static byte[] seal(Context context, byte[] aad, byte[] plaintext) {
        return ChaCha20Poly1305.seal(context.key, context.baseNonce, aad, plaintext);
    }

    public static byte[] open(byte[] recipientSecret, byte[] senderPublic, byte[] encapsulated, byte[] info, byte[] aad, byte[] ciphertext) {
        byte[] dh = Secp256k1.diffieHellman(recipientSecret, encapsulated);
        byte[] receiverPublic = Secp256k1.publicKey(recipientSecret);
        byte[] shared;
        byte mode;
        if (senderPublic == null) {
            shared = extractAndExpand(dh, concat(encapsulated, receiverPublic));
            mode = MODE_BASE;
        } else {
            shared = extractAndExpand(
                    concat(dh, Secp256k1.diffieHellman(recipientSecret, senderPublic)),
                    concat(encapsulated, receiverPublic, senderPublic));
            mode = MODE_AUTH;
        }
        Context context = schedule(mode, shared, info, encapsulated);
        return ChaCha20Poly1305.open(context.key, context.baseNonce, aad, ciphertext);
    }

    public static byte[] export(Context context, byte[] exporterContext, int length) {
        return labeledExpand(HPKE_SUITE, context.exporterSecret, ascii("sec"), exporterContext, length);
    }

    static byte[] deriveSecretKey(byte[] ikm) {
        byte[] prk = labeledExtract(KEM_SUITE, new byte[0], ascii("dkp_prk"), ikm);
        for (int counter = 0; counter < 256; counter++) {
            byte[] candidate = labeledExpand(KEM_SUITE, prk, ascii("candidate"), new byte[] {(byte) counter}, 32);
            candidate[0] = (byte) (candidate[0] & 0xff);
            BigInteger scalar = new BigInteger(1, candidate);
            if (scalar.signum() != 0 && scalar.compareTo(ORDER) < 0) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("cannot derive a secp256k1 key");
    }

    private static Context schedule(byte mode, byte[] sharedSecret, byte[] info, byte[] encapsulated) {
        byte[] pskIdHash = labeledExtract(HPKE_SUITE, new byte[0], ascii("psk_id_hash"), new byte[0]);
        byte[] infoHash = labeledExtract(HPKE_SUITE, new byte[0], ascii("info_hash"), info);
        byte[] scheduleContext = concat(new byte[] {mode}, pskIdHash, infoHash);
        byte[] secret = labeledExtract(HPKE_SUITE, sharedSecret, ascii("secret"), new byte[0]);
        return new Context(
                encapsulated,
                labeledExpand(HPKE_SUITE, secret, ascii("key"), scheduleContext, 32),
                labeledExpand(HPKE_SUITE, secret, ascii("base_nonce"), scheduleContext, 12),
                labeledExpand(HPKE_SUITE, secret, ascii("exp"), scheduleContext, 32));
    }

    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) {
        byte[] prk = labeledExtract(KEM_SUITE, new byte[0], ascii("eae_prk"), dh);
        return labeledExpand(KEM_SUITE, prk, ascii("shared_secret"), kemContext, 32);
    }

    private static byte[] labeledExtract(byte[] suite, byte[] salt, byte[] label, byte[] ikm) {
        return Hkdf.extract(salt, concat(ascii("HPKE-v1"), suite, label, ikm));
    }

    /**
     * {@code labeled_info} is {@code I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info}.
     * bitcoin-hpke 0.13, which rust-payjoin uses, expands in that order, and the
     * secp256k1 HPKE draft vectors match it.
     */
    private static byte[] labeledExpand(byte[] suite, byte[] prk, byte[] label, byte[] info, int length) {
        byte[] labeled = concat(new byte[] {(byte) (length >> 8), (byte) length}, ascii("HPKE-v1"), suite, label, info);
        return Hkdf.expand(prk, labeled, length);
    }

    private static byte[] ascii(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
}
