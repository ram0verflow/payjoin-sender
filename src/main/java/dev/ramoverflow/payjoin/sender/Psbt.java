package dev.ramoverflow.payjoin.sender;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Version-0 PSBT. The proposal is hostile: duplicate keys, bad lengths, and short buffers fail. */
final class Psbt {
    static final long MAX_MONEY = 2_100_000_000_000_000L;

    final int version;
    final int locktime;
    final List<Input> inputs;
    final List<Output> outputs;
    final int end;

    private Psbt(int version, int locktime, List<Input> inputs, List<Output> outputs, int end) {
        this.version = version;
        this.locktime = locktime;
        this.inputs = inputs;
        this.outputs = outputs;
        this.end = end;
    }

    static Psbt read(byte[] data) {
        Cursor cursor = new Cursor(data);
        if (cursor.u8() != 'p' || cursor.u8() != 's' || cursor.u8() != 'b' || cursor.u8() != 't' || cursor.u8() != 0xff) {
            throw new IllegalArgumentException("not a psbt");
        }
        byte[] unsigned = null;
        while (true) {
            byte[] key = cursor.key();
            if (key == null) {
                break;
            }
            byte[] value = cursor.value();
            if (key.length == 1 && key[0] == 0x00) {
                unsigned = value;
            }
        }
        if (unsigned == null) {
            throw new IllegalArgumentException("psbt has no unsigned transaction");
        }
        Transaction transaction = Transaction.parse(unsigned, true);
        List<Input> inputs = new ArrayList<>();
        for (TxIn txin : transaction.inputs) {
            inputs.add(Input.read(cursor, txin));
        }
        List<Output> outputs = new ArrayList<>();
        for (TxOut txout : transaction.outputs) {
            outputs.add(Output.read(cursor, txout));
        }
        return new Psbt(transaction.version, transaction.locktime, inputs, outputs, cursor.i);
    }

    long fee() {
        long inputsTotal = 0;
        long outputsTotal = 0;
        for (Input input : inputs) {
            TxOut spent = input.spent();
            if (spent == null) {
                throw new IllegalArgumentException("psbt input is missing a previous output");
            }
            inputsTotal = Math.addExact(inputsTotal, spent.value);
        }
        for (Output output : outputs) {
            outputsTotal = Math.addExact(outputsTotal, output.value);
        }
        return Math.subtractExact(inputsTotal, outputsTotal);
    }

    /** Weight of the transaction with final scripts applied, in weight units. */
    long weight() {
        boolean segwit = false;
        for (Input input : inputs) {
            if (input.finalWitness != null && !input.finalWitness.isEmpty()) {
                segwit = true;
            }
        }
        long base = 4 + varintSize(inputs.size());
        long witness = 0;
        for (Input input : inputs) {
            int script = input.finalScriptSig == null ? 0 : input.finalScriptSig.length;
            base += 40 + varintSize(script) + script;
            if (segwit) {
                List<byte[]> stack = input.finalWitness == null ? List.of() : input.finalWitness;
                witness += varintSize(stack.size());
                for (byte[] item : stack) {
                    witness += varintSize(item.length) + item.length;
                }
            }
        }
        base += varintSize(outputs.size());
        for (Output output : outputs) {
            base += 8 + varintSize(output.script.length) + output.script.length;
        }
        base += 4;
        long total = segwit ? base + 2 + witness : base;
        return base * 3 + total;
    }

    static int varintSize(int value) {
        if (value < 0xfd) {
            return 1;
        }
        if (value <= 0xffff) {
            return 3;
        }
        return 5;
    }

    static final class Input {
        final byte[] txid;
        final int vout;
        final int sequence;
        final TxOut witness;
        final Prev prev;
        final boolean partialSig;
        final boolean bip32;
        final byte[] finalScriptSig;
        final List<byte[]> finalWitness;
        final Integer sighash;
        final byte[] redeemScript;

        private Input(
                TxIn txin,
                TxOut witness,
                Prev prev,
                boolean partialSig,
                boolean bip32,
                byte[] finalScriptSig,
                List<byte[]> finalWitness,
                Integer sighash,
                byte[] redeemScript) {
            this.txid = txin.txid;
            this.vout = txin.vout;
            this.sequence = txin.sequence;
            this.witness = witness;
            this.prev = prev;
            this.partialSig = partialSig;
            this.bip32 = bip32;
            this.finalScriptSig = finalScriptSig;
            this.finalWitness = finalWitness;
            this.sighash = sighash;
            this.redeemScript = redeemScript;
            spent();
        }

        private static Input read(Cursor cursor, TxIn txin) {
            TxOut witness = null;
            Prev prev = null;
            boolean partialSig = false;
            boolean bip32 = false;
            byte[] finalScriptSig = null;
            List<byte[]> finalWitness = null;
            Integer sighash = null;
            byte[] redeemScript = null;
            while (true) {
                byte[] key = cursor.key();
                if (key == null) {
                    break;
                }
                byte[] value = cursor.value();
                int type = key[0] & 0xff;
                if (key.length != 1 && type != 0x02 && type != 0x06) {
                    continue;
                }
                switch (type) {
                    case 0x00 -> prev = Prev.parse(value);
                    case 0x01 -> witness = TxOut.parse(value);
                    case 0x02 -> partialSig = true;
                    case 0x03 -> sighash = sighash(value);
                    case 0x04 -> redeemScript = value;
                    case 0x06 -> bip32 = true;
                    case 0x07 -> finalScriptSig = value;
                    case 0x08 -> finalWitness = witnessStack(value);
                    default -> {
                        // Unknown keys are kept only for the duplicate-key check.
                    }
                }
            }
            return new Input(txin, witness, prev, partialSig, bip32, finalScriptSig, finalWitness, sighash, redeemScript);
        }

        TxOut spent() {
            if (prev == null && witness == null) {
                return null;
            }
            if (prev != null) {
                if (!Arrays.equals(prev.txid, txid)) {
                    throw new IllegalArgumentException("psbt previous transaction does not match the outpoint");
                }
                if (vout < 0 || vout >= prev.outputs.size()) {
                    throw new IllegalArgumentException("psbt previous output is out of range");
                }
                TxOut fromPrev = prev.outputs.get(vout);
                if (witness != null && (witness.value != fromPrev.value || !Arrays.equals(witness.script, fromPrev.script))) {
                    throw new IllegalArgumentException("psbt witness output does not match the previous transaction");
                }
                return fromPrev;
            }
            return witness;
        }

        boolean sameOutpoint(Input other) {
            return vout == other.vout && Arrays.equals(txid, other.txid);
        }

        private static int sighash(byte[] value) {
            if (value.length != 4) {
                throw new IllegalArgumentException("psbt sighash length is malformed");
            }
            return (value[0] & 0xff) | ((value[1] & 0xff) << 8) | ((value[2] & 0xff) << 16) | ((value[3] & 0xff) << 24);
        }

        private static List<byte[]> witnessStack(byte[] value) {
            Cursor cursor = new Cursor(value);
            int count = cursor.compact();
            List<byte[]> stack = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                stack.add(cursor.take(cursor.compact()));
            }
            if (cursor.i != value.length) {
                throw new IllegalArgumentException("psbt witness length is malformed");
            }
            return stack;
        }
    }

    static final class Output {
        final long value;
        final byte[] script;
        final boolean bip32;

        private Output(TxOut txout, boolean bip32) {
            this.value = txout.value;
            this.script = txout.script;
            this.bip32 = bip32;
        }

        private static Output read(Cursor cursor, TxOut txout) {
            boolean bip32 = false;
            while (true) {
                byte[] key = cursor.key();
                if (key == null) {
                    break;
                }
                cursor.value();
                if ((key[0] & 0xff) == 0x02) {
                    bip32 = true;
                }
            }
            return new Output(txout, bip32);
        }
    }

    static final class TxOut {
        final long value;
        final byte[] script;

        private TxOut(long value, byte[] script) {
            this.value = value;
            this.script = script;
        }

        private static TxOut parse(byte[] value) {
            Cursor cursor = new Cursor(value);
            TxOut txout = read(cursor);
            if (cursor.i != value.length) {
                throw new IllegalArgumentException("psbt output length is malformed");
            }
            return txout;
        }

        private static TxOut read(Cursor cursor) {
            return new TxOut(cursor.money(), cursor.script());
        }
    }

    private static final class Prev {
        final byte[] txid;
        final List<TxOut> outputs;

        private Prev(byte[] txid, List<TxOut> outputs) {
            this.txid = txid;
            this.outputs = outputs;
        }

        private static Prev parse(byte[] value) {
            Transaction transaction = Transaction.parse(value, false);
            return new Prev(hash256(transaction.legacy), transaction.outputs);
        }
    }

    private static final class TxIn {
        final byte[] txid;
        final int vout;
        final int sequence;
        final byte[] script;

        private TxIn(byte[] txid, int vout, int sequence, byte[] script) {
            this.txid = txid;
            this.vout = vout;
            this.sequence = sequence;
            this.script = script;
        }
    }

    private static final class Transaction {
        final int version;
        final int locktime;
        final List<TxIn> inputs;
        final List<TxOut> outputs;
        final byte[] legacy;

        private Transaction(int version, int locktime, List<TxIn> inputs, List<TxOut> outputs, byte[] legacy) {
            this.version = version;
            this.locktime = locktime;
            this.inputs = inputs;
            this.outputs = outputs;
            this.legacy = legacy;
        }

        private static Transaction parse(byte[] raw, boolean unsigned) {
            Cursor cursor = new Cursor(raw);
            int version = cursor.i32();
            boolean segwit = false;
            if (cursor.remaining() >= 2 && cursor.data[cursor.i] == 0 && cursor.data[cursor.i + 1] != 0) {
                if (unsigned) {
                    throw new IllegalArgumentException("psbt transaction is not the unsigned form");
                }
                cursor.u8();
                if (cursor.u8() != 1) {
                    throw new IllegalArgumentException("psbt transaction witness flag is malformed");
                }
                segwit = true;
            }
            int inputCount = cursor.compact();
            if (inputCount <= 0) {
                throw new IllegalArgumentException("psbt transaction is not the unsigned form");
            }
            List<TxIn> inputs = new ArrayList<>();
            for (int i = 0; i < inputCount; i++) {
                byte[] txid = cursor.take(32);
                int vout = cursor.i32();
                byte[] script = cursor.script();
                if (unsigned && script.length != 0) {
                    throw new IllegalArgumentException("psbt transaction script is not empty");
                }
                inputs.add(new TxIn(txid, vout, cursor.i32(), script));
            }
            int outputCount = cursor.compact();
            List<TxOut> outputs = new ArrayList<>();
            for (int i = 0; i < outputCount; i++) {
                outputs.add(TxOut.read(cursor));
            }
            if (segwit) {
                for (int i = 0; i < inputCount; i++) {
                    int count = cursor.compact();
                    for (int item = 0; item < count; item++) {
                        cursor.skip(cursor.compact());
                    }
                }
            }
            int locktime = cursor.i32();
            if (cursor.i != raw.length) {
                throw new IllegalArgumentException("psbt transaction has trailing bytes");
            }
            return new Transaction(version, locktime, inputs, outputs, legacy(version, inputs, outputs, locktime));
        }

        private static byte[] legacy(int version, List<TxIn> inputs, List<TxOut> outputs, int locktime) {
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            writeU32(raw, version);
            writeCompact(raw, inputs.size());
            for (TxIn input : inputs) {
                raw.writeBytes(input.txid);
                writeU32(raw, input.vout);
                writeCompact(raw, input.script.length);
                raw.writeBytes(input.script);
                writeU32(raw, input.sequence);
            }
            writeCompact(raw, outputs.size());
            for (TxOut output : outputs) {
                writeU64(raw, output.value);
                writeCompact(raw, output.script.length);
                raw.writeBytes(output.script);
            }
            writeU32(raw, locktime);
            return raw.toByteArray();
        }
    }

    private static void writeU32(ByteArrayOutputStream out, int value) {
        out.write(value);
        out.write(value >>> 8);
        out.write(value >>> 16);
        out.write(value >>> 24);
    }

    private static void writeU64(ByteArrayOutputStream out, long value) {
        for (int shift = 0; shift < 64; shift += 8) {
            out.write((int) (value >>> shift));
        }
    }

    private static void writeCompact(ByteArrayOutputStream out, int value) {
        if (value < 0xfd) {
            out.write(value);
        } else if (value <= 0xffff) {
            out.write(0xfd);
            out.write(value);
            out.write(value >>> 8);
        } else {
            out.write(0xfe);
            writeU32(out, value);
        }
    }

    private static byte[] hash256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class Cursor {
        private final byte[] data;
        private int i;
        private final List<byte[]> keys = new ArrayList<>();

        private Cursor(byte[] data) {
            this.data = data;
        }

        private byte[] key() {
            int length = compact();
            if (length == 0) {
                keys.clear();
                return null;
            }
            byte[] key = take(length);
            for (byte[] seen : keys) {
                if (Arrays.equals(seen, key)) {
                    throw new IllegalArgumentException("psbt key is duplicated");
                }
            }
            keys.add(key);
            return key;
        }

        private byte[] value() {
            return take(compact());
        }

        private int remaining() {
            return data.length - i;
        }

        private int u8() {
            if (i >= data.length) {
                throw new IllegalArgumentException("truncated psbt");
            }
            return data[i++] & 0xff;
        }

        private int i32() {
            return u8() | (u8() << 8) | (u8() << 16) | (u8() << 24);
        }

        private long money() {
            long low = u8() | ((long) u8() << 8) | ((long) u8() << 16) | ((long) u8() << 24);
            long high = u8() | ((long) u8() << 8) | ((long) u8() << 16) | ((long) u8() << 24);
            long value = (high << 32) | low;
            if (value < 0 || value > MAX_MONEY) {
                throw new IllegalArgumentException("psbt amount is oversized");
            }
            return value;
        }

        private byte[] script() {
            int length = compact();
            if (length > 10_000) {
                throw new IllegalArgumentException("psbt script is oversized");
            }
            return take(length);
        }

        private void skip(int length) {
            take(length);
        }

        private byte[] take(int length) {
            if (length < 0 || length > data.length - i) {
                throw new IllegalArgumentException("truncated psbt");
            }
            int start = i;
            i += length;
            return Arrays.copyOfRange(data, start, i);
        }

        private int compact() {
            int first = u8();
            if (first < 0xfd) {
                return first;
            }
            if (first == 0xfd) {
                int value = u8() | (u8() << 8);
                if (value < 0xfd) {
                    throw new IllegalArgumentException("psbt length is malformed");
                }
                return value;
            }
            if (first == 0xfe) {
                long value = u8() | ((long) u8() << 8) | ((long) u8() << 16) | ((long) u8() << 24);
                if (value < 0x10000 || value > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("psbt length is malformed");
                }
                return (int) value;
            }
            throw new IllegalArgumentException("psbt length is too large");
        }
    }
}
