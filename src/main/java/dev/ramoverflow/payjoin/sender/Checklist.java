package dev.ramoverflow.payjoin.sender;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Sender checklist from rust-payjoin. Sighash types and the per-input weight
 * estimate are included even though BIP 78's text does not state them that way.
 * The proposal bytes are not rewritten.
 */
final class Checklist {
    private Checklist() {}

    static void vetOriginal(String originalBase64, byte[] payee, Long amountSats) {
        Psbt original = parseOriginal(originalBase64);
        for (Psbt.Input input : original.inputs) {
            if (input.spent() == null) {
                throw new IllegalArgumentException("original psbt input is missing a previous output");
            }
            if (input.sighash != null && !commitsToAll(input.sighash)) {
                throw new IllegalArgumentException("original psbt sighash does not commit to all inputs and outputs");
            }
        }
        int found = 0;
        long paid = 0;
        for (Psbt.Output output : original.outputs) {
            if (Arrays.equals(output.script, payee)) {
                found++;
                paid = output.value;
            }
        }
        if (found != 1) {
            throw new IllegalArgumentException("original psbt must pay the uri address once");
        }
        if (amountSats != null && paid != amountSats) {
            throw new IllegalArgumentException("original psbt amount does not match the uri");
        }
        if (original.fee() < 0) {
            throw new IllegalArgumentException("original psbt fee is negative");
        }
    }

    static void accept(
            String originalBase64,
            byte[] proposalBytes,
            byte[] payee,
            boolean substitution,
            Integer feeIndex,
            Long feeSats,
            Long minFee) {
        Psbt original = parseOriginal(originalBase64);
        Psbt proposal = parseProposal(proposalBytes);
        if (proposal.version != original.version) {
            reject("proposal version does not match");
        }
        if (proposal.locktime != original.locktime) {
            reject("proposal locktime does not match");
        }
        checkInputs(original, proposal);
        long contributed = checkOutputs(original, proposal, payee, substitution, feeIndex, feeSats);
        checkFees(original, proposal, contributed, minFee);
    }

    private static void checkInputs(Psbt original, Psbt proposal) {
        int next = 0;
        int firstSequence = original.inputs.get(0).sequence;
        for (Psbt.Input proposed : proposal.inputs) {
            if (proposed.bip32) {
                reject("proposal input contains key paths");
            }
            if (proposed.partialSig) {
                reject("proposal input contains partial signatures");
            }
            if (next < original.inputs.size() && proposed.sameOutpoint(original.inputs.get(next))) {
                Psbt.Input sender = original.inputs.get(next);
                if (proposed.sequence != sender.sequence) {
                    reject("proposal changed a sender input sequence");
                }
                if (proposed.finalScriptSig != null) {
                    reject("proposal finalized a sender input script");
                }
                if (proposed.finalWitness != null) {
                    reject("proposal finalized a sender input witness");
                }
                if (proposed.sighash != null && !commitsToAll(proposed.sighash)) {
                    reject("proposal sighash does not commit to all inputs and outputs");
                }
                next++;
            } else {
                if (proposed.finalScriptSig == null && proposed.finalWitness == null) {
                    reject("proposal receiver input is not finalized");
                }
                if (proposed.spent() == null) {
                    reject("proposal receiver input is missing a previous output");
                }
                if (proposed.sequence != firstSequence) {
                    reject("proposal mixes input sequences");
                }
            }
        }
        if (next != original.inputs.size()) {
            reject("proposal is missing a sender input");
        }
    }

    private static long checkOutputs(
            Psbt original, Psbt proposal, byte[] payee, boolean substitution, Integer feeIndex, Long feeSats) {
        int next = 0;
        long contributed = 0;
        for (Psbt.Output proposed : proposal.outputs) {
            if (proposed.bip32) {
                reject("proposal output contains key paths");
            }
            if (next >= original.outputs.size()) {
                continue;
            }
            Psbt.Output current = original.outputs.get(next);
            boolean feeOutput = feeIndex != null
                    && next == feeIndex
                    && Arrays.equals(proposed.script, current.script);
            if (feeOutput) {
                if (proposed.value < current.value) {
                    contributed = current.value - proposed.value;
                    if (contributed > feeSats) {
                        reject("proposal fee contribution exceeds the maximum");
                    }
                }
                next++;
            } else if (Arrays.equals(current.script, payee)) {
                if (!substitution
                        && (!Arrays.equals(proposed.script, current.script) || proposed.value < current.value)) {
                    reject("proposal substitutes the payment output");
                }
                next++;
            } else if (Arrays.equals(proposed.script, current.script)) {
                if (proposed.value < current.value) {
                    reject("proposal decreased an output value");
                }
                next++;
            }
        }
        if (next != original.outputs.size()) {
            reject("proposal is missing a sender output");
        }
        return contributed;
    }

    private static void checkFees(Psbt original, Psbt proposal, long contributed, Long minFee) {
        long originalFee = inputTotal(original, original);
        long proposedFee = inputTotal(original, proposal);
        for (Psbt.Output output : original.outputs) {
            originalFee -= output.value;
        }
        for (Psbt.Output output : proposal.outputs) {
            proposedFee -= output.value;
        }
        if (originalFee < 0 || proposedFee < originalFee) {
            reject("proposal decreased the absolute fee");
        }
        if (contributed > proposedFee - originalFee) {
            reject("proposal fee contribution is not only paying fee");
        }
        long extra = additionalWeight(original, proposal);
        if (contributed > allowance(originalFee, original.weight(), extra)) {
            reject("proposal fee contribution pays for more than the added inputs");
        }
        if (minFee != null && minFee > 0) {
            long proposedRate = rate(proposedFee, proposal.weight());
            if (proposedRate < Math.multiplyExact(minFee, 250L)) {
                reject("proposal fee rate is below the minimum");
            }
        }
    }

    private static long inputTotal(Psbt original, Psbt source) {
        long total = 0;
        int next = 0;
        for (Psbt.Input proposed : source.inputs) {
            Psbt.TxOut spent;
            if (source == original) {
                spent = proposed.spent();
            } else if (next < original.inputs.size() && proposed.sameOutpoint(original.inputs.get(next))) {
                spent = original.inputs.get(next).spent();
                next++;
            } else {
                spent = proposed.spent();
            }
            if (spent == null) {
                throw new InternalException("original psbt input is missing a previous output");
            }
            total = Math.addExact(total, spent.value);
        }
        return total;
    }

    private static long additionalWeight(Psbt original, Psbt proposal) {
        List<byte[]> scripts = new ArrayList<>();
        for (Psbt.Input input : original.inputs) {
            scripts.add(input.spent().script);
        }
        long extra = 0;
        int next = 0;
        for (Psbt.Input proposed : proposal.inputs) {
            byte[] script;
            if (next < original.inputs.size() && proposed.sameOutpoint(original.inputs.get(next))) {
                script = original.inputs.get(next).spent().script;
                next++;
            } else {
                script = proposed.spent().script;
            }
            if (!contains(scripts, script)) {
                extra += expectedWeight(proposed, script);
            }
        }
        return extra;
    }

    private static boolean contains(List<byte[]> scripts, byte[] script) {
        for (byte[] candidate : scripts) {
            if (Arrays.equals(candidate, script)) {
                return true;
            }
        }
        return false;
    }

    private static long expectedWeight(Psbt.Input input, byte[] script) {
        if (isP2pkh(script)) {
            return predicted(107, new int[0]);
        }
        if (isP2wpkh(script)) {
            return predicted(0, new int[] {72, 33});
        }
        if (isP2sh(script)) {
            byte[] redeem = redeemScript(input);
            if (redeem != null && isWitnessProgram(redeem) && isP2wpkh(redeem)) {
                return predicted(23, new int[] {72, 33});
            }
            reject("additional input weight is not supported");
        }
        if (isP2wsh(script) || isP2tr(script)) {
            if (input.finalWitness == null || input.finalWitness.isEmpty()) {
                reject("additional input weight is not supported");
            }
            int[] lengths = new int[input.finalWitness.size()];
            for (int i = 0; i < lengths.length; i++) {
                lengths[i] = input.finalWitness.get(i).length;
            }
            return predicted(0, lengths);
        }
        reject("additional input weight is not supported");
        return 0;
    }

    private static byte[] redeemScript(Psbt.Input input) {
        if (input.finalScriptSig != null) {
            return lastPush(input.finalScriptSig);
        }
        return input.redeemScript;
    }

    private static byte[] lastPush(byte[] script) {
        int index = 0;
        byte[] last = null;
        while (index < script.length) {
            int opcode = script[index++] & 0xff;
            int length;
            if (opcode >= 1 && opcode <= 75) {
                length = opcode;
            } else if (opcode == 0x4c) {
                if (index >= script.length) {
                    return null;
                }
                length = script[index++] & 0xff;
            } else if (opcode == 0x4d) {
                if (index + 1 >= script.length) {
                    return null;
                }
                length = (script[index] & 0xff) | ((script[index + 1] & 0xff) << 8);
                index += 2;
            } else if (opcode == 0x4e) {
                if (index + 3 >= script.length) {
                    return null;
                }
                length = (script[index] & 0xff)
                        | ((script[index + 1] & 0xff) << 8)
                        | ((script[index + 2] & 0xff) << 16)
                        | ((script[index + 3] & 0xff) << 24);
                index += 4;
            } else {
                return null;
            }
            if (length < 0 || index > script.length - length) {
                return null;
            }
            last = Arrays.copyOfRange(script, index, index + length);
            index += length;
        }
        return last;
    }

    private static long predicted(int scriptLength, int[] witnessItems) {
        int scriptSize = scriptLength + Psbt.varintSize(scriptLength);
        int witnessSize = 0;
        if (witnessItems.length > 0) {
            witnessSize = Psbt.varintSize(witnessItems.length);
            for (int length : witnessItems) {
                witnessSize += length + Psbt.varintSize(length);
            }
        }
        return (long) scriptSize * 4 + witnessSize + 160;
    }

    private static long allowance(long feeSats, long weight, long extraWeight) {
        return (Math.multiplyExact(rate(feeSats, weight), extraWeight) + 999) / 1000;
    }

    private static long rate(long feeSats, long weight) {
        if (weight <= 0) {
            throw new InternalException("transaction weight is zero");
        }
        return Math.multiplyExact(feeSats, 1000L) / weight;
    }

    private static boolean commitsToAll(int sighash) {
        if ((sighash & ~0xff) != 0) {
            return false;
        }
        int low = sighash & 0xff;
        return low == 0x00 || low == 0x01;
    }

    private static boolean isP2pkh(byte[] script) {
        return script.length == 25
                && script[0] == 0x76
                && script[1] == (byte) 0xa9
                && script[2] == 20
                && script[23] == (byte) 0x88
                && script[24] == (byte) 0xac;
    }

    private static boolean isP2sh(byte[] script) {
        return script.length == 23 && script[0] == (byte) 0xa9 && script[1] == 20 && script[22] == (byte) 0x87;
    }

    private static boolean isP2wpkh(byte[] script) {
        return script.length == 22 && script[0] == 0x00 && script[1] == 20;
    }

    private static boolean isP2wsh(byte[] script) {
        return script.length == 34 && script[0] == 0x00 && script[1] == 32;
    }

    private static boolean isP2tr(byte[] script) {
        return script.length == 34 && script[0] == 0x51 && script[1] == 32;
    }

    private static boolean isWitnessProgram(byte[] script) {
        if (script.length < 4 || script.length > 42) {
            return false;
        }
        int push = script[1] & 0xff;
        if (push < 2 || push > 40 || script.length - 2 != push) {
            return false;
        }
        int version = script[0] & 0xff;
        return version == 0x00 || (version >= 0x51 && version <= 0x60);
    }

    private static Psbt parseOriginal(String originalBase64) {
        try {
            byte[] raw = Base64.getDecoder().decode(originalBase64);
            Psbt original = Psbt.read(raw);
            if (original.end != raw.length) {
                throw new IllegalArgumentException("original psbt has trailing bytes");
            }
            return original;
        } catch (RuntimeException e) {
            throw new InternalException("original psbt failed to parse");
        }
    }

    private static Psbt parseProposal(byte[] proposalBytes) {
        try {
            Psbt proposal = Psbt.read(proposalBytes);
            if (proposal.end != proposalBytes.length) {
                throw new IllegalArgumentException("proposal psbt has trailing bytes");
            }
            return proposal;
        } catch (RuntimeException e) {
            throw new CounterpartyException("proposal psbt is malformed", e);
        }
    }

    private static void reject(String message) {
        throw new CounterpartyException(message);
    }
}
