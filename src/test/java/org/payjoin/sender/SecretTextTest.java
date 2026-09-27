package org.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SecretTextTest {
    @Test
    void ignoresASecretThatTheInputAlreadyContained() {
        byte[] input = Hex.encode(FuzzKeys.reply()).getBytes(StandardCharsets.ISO_8859_1);
        SecretText.refuse(
                new IllegalArgumentException(new String(input, StandardCharsets.ISO_8859_1)), input, FuzzKeys.reply());
    }

    @Test
    void ignoresASecretSplitByBytesThatAreDropped() {
        String hex = Hex.encode(FuzzKeys.reply());
        int mid = hex.length() / 2;
        byte[] split = new byte[hex.length() + 1];
        for (int i = 0; i < mid; i++) {
            split[i] = (byte) hex.charAt(i);
        }
        split[mid] = 0x05;
        for (int i = mid; i < hex.length(); i++) {
            split[i + 1] = (byte) hex.charAt(i);
        }
        SecretText.refuse(new IllegalArgumentException(hex), split, FuzzKeys.reply());
    }

    @Test
    void rejectsASecretThatTheInputDidNotContain() {
        String leaked = Hex.encode(FuzzKeys.reply());
        assertThrows(
                AssertionError.class,
                () -> SecretText.refuse(new IllegalArgumentException(leaked), new byte[] {1}, FuzzKeys.reply()));
    }
}
