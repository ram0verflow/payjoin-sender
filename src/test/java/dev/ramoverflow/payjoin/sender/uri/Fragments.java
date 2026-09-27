package dev.ramoverflow.payjoin.sender.uri;

/** Test-only access to the package-private fragment codec. */
public final class Fragments {
    private Fragments() {}

    public static String encode(String hrp, byte[] data) {
        return Bech32.encode(hrp, data);
    }
}
