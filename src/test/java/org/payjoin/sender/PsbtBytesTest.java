package org.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

class PsbtBytesTest {
    @Test
    void findsTheEndAndStripsZeroPadding() {
        byte[] psbt = minimalPsbt();
        assertEquals(psbt.length, PsbtBytes.end(psbt));
        byte[] padded = new byte[psbt.length + 10];
        System.arraycopy(psbt, 0, padded, 0, psbt.length);
        assertArrayEquals(psbt, PsbtBytes.proposal(padded));
    }

    @Test
    void rejectsTruncationTrailingJunkAndAReceiverError() {
        byte[] psbt = minimalPsbt();
        assertThrows(IllegalArgumentException.class, () -> PsbtBytes.end(new byte[] {1, 2, 3}));
        byte[] shortPsbt = java.util.Arrays.copyOf(psbt, psbt.length - 1);
        assertThrows(IllegalArgumentException.class, () -> PsbtBytes.end(shortPsbt));
        byte[] junk = psbt.clone();
        byte[] padded = new byte[psbt.length + 1];
        System.arraycopy(junk, 0, padded, 0, junk.length);
        padded[padded.length - 1] = 1;
        assertThrows(CounterpartyException.class, () -> PsbtBytes.proposal(padded));
        byte[] error = new byte[] {'{', '"', 'e', '"', ':', '1', '}', 0, 0};
        assertThrows(CounterpartyException.class, () -> PsbtBytes.proposal(error));
    }

    static byte[] minimalPsbt() {
        byte[] transaction = new byte[60];
        transaction[0] = 1;
        transaction[4] = 1;
        transaction[42] = (byte) 0xff;
        transaction[43] = (byte) 0xff;
        transaction[44] = (byte) 0xff;
        transaction[45] = (byte) 0xff;
        transaction[46] = 1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('p');
        out.write('s');
        out.write('b');
        out.write('t');
        out.write(0xff);
        out.write(0x01);
        out.write(0x00);
        out.write(0x3c);
        out.write(transaction, 0, transaction.length);
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);
        return out.toByteArray();
    }
}
