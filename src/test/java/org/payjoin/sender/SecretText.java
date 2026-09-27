package org.payjoin.sender;

/**
 * Fails a fuzz input whose thrown text contains a fixed test secret that
 * was not already in the input. Echoing the input is not a leak.
 */
public final class SecretText {
    private SecretText() {}

    public static void refuse(Throwable error, byte[] input, byte[]... secrets) {
        String echoed = printable(input);
        for (Throwable current = error; current != null; current = current.getCause()) {
            String message = current.getMessage();
            if (message == null) {
                continue;
            }
            for (byte[] secret : secrets) {
                String needle = Hex.encode(secret);
                if (message.contains(needle) && !echoed.contains(needle)) {
                    throw new AssertionError("exception text contains a test secret");
                }
            }
        }
    }

    private static String printable(byte[] input) {
        StringBuilder out = new StringBuilder(input.length);
        for (byte value : input) {
            int b = value & 0xff;
            if (b >= 0x20 && b <= 0x7e) {
                out.append((char) b);
            }
        }
        return out.toString();
    }
}
