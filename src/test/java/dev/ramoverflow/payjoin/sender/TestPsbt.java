package dev.ramoverflow.payjoin.sender;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Builds the small PSBTs the checklist tests mutate. */
final class TestPsbt {
    int version = 2;
    int locktime;
    final List<In> inputs = new ArrayList<>();
    final List<Out> outputs = new ArrayList<>();

    static TestPsbt funded(byte[] payee) {
        TestPsbt psbt = new TestPsbt();
        psbt.inputs.add(In.witness(bytes(0x11, 32), 0, 0xfffffffe, 100_000, p2wpkh(0x11)));
        psbt.outputs.add(new Out(50_000, payee));
        psbt.outputs.add(new Out(40_000, p2wpkh(0x22)));
        return psbt;
    }

    static byte[] p2wpkh(int tag) {
        byte[] script = new byte[22];
        script[1] = 20;
        Arrays.fill(script, 2, 22, (byte) tag);
        return script;
    }

    static byte[] bytes(int value, int length) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    TestPsbt copy() {
        TestPsbt copy = new TestPsbt();
        copy.version = version;
        copy.locktime = locktime;
        for (In input : inputs) {
            copy.inputs.add(input.copy());
        }
        for (Out output : outputs) {
            copy.outputs.add(new Out(output.value, output.script.clone()));
        }
        return copy;
    }

    byte[] bytes() {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        raw.write('p');
        raw.write('s');
        raw.write('b');
        raw.write('t');
        raw.write(0xff);
        byte[] transaction = transaction();
        raw.write(0x01);
        raw.write(0x00);
        writeCompact(raw, transaction.length);
        raw.writeBytes(transaction);
        raw.write(0x00);
        for (In input : inputs) {
            input.write(raw);
            raw.write(0x00);
        }
        for (Out output : outputs) {
            output.write(raw);
            raw.write(0x00);
        }
        return raw.toByteArray();
    }

    private byte[] transaction() {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        writeU32(raw, version);
        writeCompact(raw, inputs.size());
        for (In input : inputs) {
            raw.writeBytes(input.txid);
            writeU32(raw, input.vout);
            writeCompact(raw, 0);
            writeU32(raw, input.sequence);
        }
        writeCompact(raw, outputs.size());
        for (Out output : outputs) {
            writeU64(raw, output.value);
            writeCompact(raw, output.script.length);
            raw.writeBytes(output.script);
        }
        writeU32(raw, locktime);
        return raw.toByteArray();
    }

    static void writeU32(ByteArrayOutputStream out, int value) {
        out.write(value);
        out.write(value >>> 8);
        out.write(value >>> 16);
        out.write(value >>> 24);
    }

    static void writeU64(ByteArrayOutputStream out, long value) {
        for (int shift = 0; shift < 64; shift += 8) {
            out.write((int) (value >>> shift));
        }
    }

    static void writeCompact(ByteArrayOutputStream out, int value) {
        if (value < 0xfd) {
            out.write(value);
        } else {
            out.write(0xfd);
            out.write(value);
            out.write(value >>> 8);
        }
    }

    static final class In {
        byte[] txid;
        int vout;
        int sequence;
        Long witnessValue;
        byte[] witnessScript;
        byte[] nonWitness;
        boolean bip32;
        boolean partial;
        byte[] finalScriptSig;
        byte[][] finalWitness;
        Integer sighash;

        static In witness(byte[] txid, int vout, int sequence, long value, byte[] script) {
            In input = new In();
            input.txid = txid;
            input.vout = vout;
            input.sequence = sequence;
            input.witnessValue = value;
            input.witnessScript = script;
            return input;
        }

        In copy() {
            In copy = new In();
            copy.txid = txid.clone();
            copy.vout = vout;
            copy.sequence = sequence;
            copy.witnessValue = witnessValue;
            copy.witnessScript = witnessScript == null ? null : witnessScript.clone();
            copy.nonWitness = nonWitness == null ? null : nonWitness.clone();
            copy.bip32 = bip32;
            copy.partial = partial;
            copy.finalScriptSig = finalScriptSig == null ? null : finalScriptSig.clone();
            copy.finalWitness = finalWitness == null ? null : finalWitness.clone();
            copy.sighash = sighash;
            return copy;
        }

        void write(ByteArrayOutputStream raw) {
            if (nonWitness != null) {
                raw.write(0x01);
                raw.write(0x00);
                writeCompact(raw, nonWitness.length);
                raw.writeBytes(nonWitness);
            }
            if (witnessValue != null) {
                raw.write(0x01);
                raw.write(0x01);
                byte[] body = new byte[8 + 1 + witnessScript.length];
                for (int shift = 0; shift < 64; shift += 8) {
                    body[shift / 8] = (byte) (witnessValue >>> shift);
                }
                body[8] = (byte) witnessScript.length;
                System.arraycopy(witnessScript, 0, body, 9, witnessScript.length);
                writeCompact(raw, body.length);
                raw.writeBytes(body);
            }
            if (partial) {
                raw.write(34);
                raw.write(0x02);
                raw.writeBytes(bytes(0x02, 33));
                raw.write(1);
                raw.write(0x30);
            }
            if (sighash != null) {
                raw.write(0x01);
                raw.write(0x03);
                raw.write(4);
                writeU32(raw, sighash);
            }
            if (bip32) {
                raw.write(34);
                raw.write(0x06);
                raw.writeBytes(bytes(0x02, 33));
                raw.write(4);
                writeU32(raw, 0);
            }
            if (finalScriptSig != null) {
                raw.write(0x01);
                raw.write(0x07);
                writeCompact(raw, finalScriptSig.length);
                raw.writeBytes(finalScriptSig);
            }
            if (finalWitness != null) {
                raw.write(0x01);
                raw.write(0x08);
                ByteArrayOutputStream stack = new ByteArrayOutputStream();
                writeCompact(stack, finalWitness.length);
                for (byte[] item : finalWitness) {
                    writeCompact(stack, item.length);
                    stack.writeBytes(item);
                }
                byte[] encoded = stack.toByteArray();
                writeCompact(raw, encoded.length);
                raw.writeBytes(encoded);
            }
        }
    }

    static final class Out {
        long value;
        byte[] script;
        boolean bip32;

        Out(long value, byte[] script) {
            this.value = value;
            this.script = script;
        }

        void write(ByteArrayOutputStream raw) {
            if (!bip32) {
                return;
            }
            raw.write(34);
            raw.write(0x02);
            raw.writeBytes(bytes(0x03, 33));
            raw.write(4);
            writeU32(raw, 0);
        }
    }
}
