package dev.ramoverflow.payjoin.sender;

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
        CounterpartyException rejected =
                assertThrows(CounterpartyException.class, () -> PsbtBytes.proposal(error));
        assertEquals("receiver rejected the original: {\"e\":1}", rejected.getMessage());
        assertThrows(IllegalArgumentException.class, () -> PsbtBytes.end(duplicatedKey(psbt)));
        assertThrows(IllegalArgumentException.class, () -> PsbtBytes.end(nonMinimalLength()));
        assertThrows(IllegalArgumentException.class, () -> PsbtBytes.end(oversizedLength(psbt)));
        assertThrows(IllegalArgumentException.class, () -> PsbtBytes.end(malformedWitness()));
    }

    @Test
    void dropsNonPrintableBytesFromAReceiverError() {
        byte[] error = new byte[] {'{', 0x01, 'n', 'o', 0x7f, (byte) 0xe9, '!', 0, 0};
        CounterpartyException rejected =
                assertThrows(CounterpartyException.class, () -> PsbtBytes.proposal(error));
        assertEquals("receiver rejected the original: {no!", rejected.getMessage());
    }

    private static byte[] duplicatedKey(byte[] psbt) {
        int key = 63;
        byte[] extra = java.util.Arrays.copyOf(psbt, psbt.length + key);
        System.arraycopy(extra, 5, extra, 5 + key, psbt.length - 5);
        System.arraycopy(psbt, 5, extra, 5, key);
        return extra;
    }

    private static byte[] nonMinimalLength() {
        byte[] psbt = minimalPsbt();
        byte[] out = new byte[psbt.length + 2];
        out[0] = psbt[0];
        out[1] = psbt[1];
        out[2] = psbt[2];
        out[3] = psbt[3];
        out[4] = psbt[4];
        out[5] = (byte) 0xfd;
        out[6] = 1;
        out[7] = 0;
        System.arraycopy(psbt, 6, out, 8, psbt.length - 6);
        return out;
    }

    private static byte[] oversizedLength(byte[] psbt) {
        byte[] out = psbt.clone();
        out[out.length - 3] = (byte) 0xff;
        return out;
    }

    private static byte[] malformedWitness() {
        byte[] psbt = minimalPsbt();
        byte[] out = java.util.Arrays.copyOf(psbt, psbt.length + 4);
        out[69] = 0x01;
        out[70] = 0x01;
        out[71] = 0x01;
        out[72] = (byte) 0xff;
        out[73] = 0x00;
        out[74] = 0x00;
        return out;
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
