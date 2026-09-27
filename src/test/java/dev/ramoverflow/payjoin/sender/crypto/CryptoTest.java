package dev.ramoverflow.payjoin.sender.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Random;
import org.junit.jupiter.api.Test;

/** RFC test vectors and test-only keys. Do not use these scalars as wallets. */
class CryptoTest {
    @Test
    void hkdfMatchesRfc5869Case1() {
        byte[] ikm = new byte[22];
        java.util.Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Hkdf.extract(salt, ikm);
        byte[] okm = Hkdf.expand(prk, info, 42);
        assertArrayEquals(
                hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
                okm);
    }

    @Test
    void chaCha20Poly1305MatchesRfc8439() {
        byte[] key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = hex("070000004041424344454647");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = hex(
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        byte[] sealed = ChaCha20Poly1305.seal(key, nonce, aad, plaintext);
        assertArrayEquals(
                hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"),
                sealed);
        assertArrayEquals(plaintext, ChaCha20Poly1305.open(key, nonce, aad, sealed));
        byte[] tampered = sealed.clone();
        tampered[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> ChaCha20Poly1305.open(key, nonce, aad, tampered));
    }

    @Test
    void secp256k1PublicKeyMatchesTheHpkeDraft() {
        byte[] secret = hex("4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643");
        byte[] expected = hex(
                "04e660b55a28899c472ca023dce35f23da3cf16677dbdce9ed25353bd8b70cbb8bee0abd2cc8936aee263a08d5b2a15d29a16d12b75fda63b9c614c477af165e2d");
        assertArrayEquals(expected, Secp256k1.publicKey(secret));
        byte[] other = hex("1300156862599d00ecbb066644bf4d4505b56a9b235eae7a8632defc4335d5c0");
        assertArrayEquals(
                Secp256k1.diffieHellman(secret, Secp256k1.publicKey(other)),
                Secp256k1.diffieHellman(other, expected));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.publicKey(new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.diffieHellman(secret, new byte[] {0x04}));
    }

    @Test
    void elligatorSwiftDecodesTheZeroEncoding() {
        byte[] encoded = new byte[64];
        byte[] point = ElligatorSwift.decode(encoded);
        assertArrayEquals(
                hex("04edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c"),
                java.util.Arrays.copyOf(point, 33));
        assertEquals(false, (point[64] & 1) == 1);
        assertDecoded(
                "000000000000000000000000000000000000000000000000000000000000000001d3475bf7655b0fb2d852921035b2ef607f49069b97454e6795251062741771",
                "b5da00b73cd6560520e7c364086e7cd23a34bf60d0e707be9fc34d4cd5fdfa2c",
                true);
        assertDecoded(
                "0ffde9ca81d751e9cdaffc1a50779245320b28996dbaf32f822f20117c22fbd6c74d99efceaa550f1ad1c0f43f46e7ff1ee3bd0162b7bf55f2965da9c3450646",
                "74e880b3ffd18fe3cddf7902522551ddf97fa4a35a3cfda8197f947081a57b8f",
                false);
        assertThrows(IllegalArgumentException.class, () -> ElligatorSwift.decode(new byte[63]));
    }

    @Test
    void elligatorSwiftRoundTripsADraftPublicKey() {
        byte[] publicKey = Secp256k1.publicKey(
                hex("4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643"));
        byte[] encoded = ElligatorSwift.encode(publicKey, new Random(1));
        assertArrayEquals(publicKey, ElligatorSwift.decode(encoded));
    }

    @Test
    void hpkeBaseMatchesDraftWahbyChaChaVector() {
        byte[] info = hex("609dcb9844f8412343191f93add1177186c03a36");
        byte[] ikmE = hex("77caf1617fb3723972a56cd2085081c9f66baae825ce5f363c0a86ec87013fa0");
        byte[] receiver = hex(
                "04e660b55a28899c472ca023dce35f23da3cf16677dbdce9ed25353bd8b70cbb8bee0abd2cc8936aee263a08d5b2a15d29a16d12b75fda63b9c614c477af165e2d");
        Hpke.Context context = Hpke.setupBase(ikmE, receiver, info);
        assertArrayEquals(
                hex("0471788be0ccf916302c4f2225bba89a0ff3832df1fe50b48d8ccb910be74e30241428ba6de731ccf538ded2913febdfe14b2648fafb8fdd35b8aa91804c706076"),
                context.encapsulatedKey());
        assertArrayEquals(hex("4c260fe82e8c3737e7a70c3223cb16fc205682255389ad4bc3e7fae42c46b062"), context.key());
        assertArrayEquals(hex("e035bbf3c39ff5a7196cfe84"), context.baseNonce());
        assertArrayEquals(hex("83e82aad90186ddd7e1db090c840ee70eb6cac7531b64dc52a12997462c8d0d8"), context.exporterSecret());
        byte[] sealed = Hpke.seal(context, new byte[0], hex("00"));
        assertArrayEquals(hex("91b1b5aa4da10ee5694206ee2b6f422691"), sealed);
        byte[] recipient = hex("4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643");
        assertArrayEquals(hex("00"), Hpke.open(recipient, null, context.encapsulatedKey(), info, new byte[0], sealed));
    }

    @Test
    void hpkeAuthMatchesDraftWahbyVector() {
        byte[] info = hex("42bb2361c10ad20c7f7403d3e048f8f74139258a");
        byte[] ikmE = hex("f402a160b0dd43a5490e9315dd8ea386eb3b2bde9e252857e8a3132fa084506b");
        // The draft text repeats skRm and pkRm as skSm and pkSm. The sender
        // secret that matches the published key schedule is DeriveKeyPair(ikmS).
        byte[] sender = Hpke.deriveSecretKey(hex("e9e68de251a00dcf0d91ca20883153bb69b912df0ba9c20938407c787f44ea67"));
        byte[] receiver = hex(
                "04a6e334bb434dcf340fa2a8267ed828b23632de1f346b8acd7a5b8e83b9bc3f58bbfabfc27dad4cbc30230de97bada0568c73f1ee877a885f5a3754bfc2287c84");
        Hpke.Context context = Hpke.setupAuth(ikmE, sender, receiver, info);
        assertArrayEquals(
                hex("04de99438fc76aaec2117df2346593c16f0a70ea9695ca7651aff895463b91e3f3c846925784ddabd6b00b5094c10ba3b11bb9ff8b11ff2e853ac03373f09d9109"),
                context.encapsulatedKey());
        assertArrayEquals(hex("f18103a860ae1eee5147aec66c2111ccc937529f9e0ba499038471326daa205e"), context.key());
        assertArrayEquals(hex("a1172b6040d1f7da83916d94"), context.baseNonce());
        assertArrayEquals(
                hex("89125c238053ad3cefb2a0acdb8da1ce89785dba613a0ca83ed78035c51f3667"),
                context.exporterSecret());
        byte[] sealed = Hpke.seal(context, new byte[0], hex("ff"));
        assertArrayEquals(hex("8fd054aa45d2b6765c0570cbf0763a64cf"), sealed);
        byte[] recipient = hex("38aca581ad6a6a202fa89ac49f89650fac018b7f1d724a72040fea497ed95b84");
        assertArrayEquals(
                hex("ff"),
                Hpke.open(recipient, Secp256k1.publicKey(sender), context.encapsulatedKey(), info, new byte[0], sealed));
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 1;
        assertThrows(
                IllegalArgumentException.class,
                () -> Hpke.open(recipient, Secp256k1.publicKey(sender), context.encapsulatedKey(), info, new byte[0], tampered));
    }

    private static void assertDecoded(String encoding, String x, boolean oddY) {
        byte[] point = ElligatorSwift.decode(hex(encoding));
        assertArrayEquals(hex("04" + x), java.util.Arrays.copyOf(point, 33));
        assertEquals(oddY, (point[64] & 1) == 1);
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
