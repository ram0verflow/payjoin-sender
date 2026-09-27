package dev.ramoverflow.payjoin.sender.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** RFC 8439 ChaCha20-Poly1305, 32-byte key and 12-byte nonce. */
public final class ChaCha20Poly1305 {
    private ChaCha20Poly1305() {}

    /** Encrypts and appends the 16-byte tag. */
    public static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        return transform(Cipher.ENCRYPT_MODE, key, nonce, aad, plaintext);
    }

    /** Decrypts a ciphertext that ends with its tag. */
    public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) {
        return transform(Cipher.DECRYPT_MODE, key, nonce, aad, ciphertext);
    }

    private static byte[] transform(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) {
        if (key.length != 32 || nonce.length != 12) {
            throw new IllegalArgumentException("ChaCha20-Poly1305 key or nonce has the wrong length");
        }
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("ChaCha20-Poly1305 failed", e);
        }
    }
}
