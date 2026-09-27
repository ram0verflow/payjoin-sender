package dev.ramoverflow.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class ChecklistTest {
    private final byte[] payee = TestPsbt.p2wpkh(0x33);

    @Test
    void acceptsAnUnchangedProposalAndOneThatAddsAnInput() {
        TestPsbt original = TestPsbt.funded(payee);
        accept(original, false, 1, 1_000L, 2L);
        TestPsbt added = original.copy();
        added.inputs.add(finalized(TestPsbt.bytes(0x44, 32), 10_000, TestPsbt.p2wpkh(0x44)));
        accept(added, false, null, null, null);
        TestPsbt substituted = original.copy();
        substituted.outputs.get(0).script = TestPsbt.p2wpkh(0x55);
        accept(substituted, true, null, null, null);
        TestPsbt signed = original.copy();
        signed.inputs.get(0).sighash = 1;
        accept(signed, false, null, null, null);
    }

    @Test
    void rejectsEachBrokenChecklistRule() {
        assertAll(
                () -> reject(version(), false, null, null, null),
                () -> reject(locktime(), false, null, null, null),
                () -> reject(inputKeyPath(), false, null, null, null),
                () -> reject(partialSignature(), false, null, null, null),
                () -> reject(senderSequence(), false, null, null, null),
                () -> reject(senderScript(), false, null, null, null),
                () -> reject(senderWitness(), false, null, null, null),
                () -> reject(sighash(), false, null, null, null),
                () -> reject(receiverNotFinalized(), false, null, null, null),
                () -> reject(receiverMissingOutput(), false, null, null, null),
                () -> reject(mixedSequence(), false, null, null, null),
                () -> reject(missingInput(), false, null, null, null),
                () -> reject(outputKeyPath(), false, null, null, null),
                () -> reject(contributionExceedsMaximum(), false, 1, 50L, null),
                () -> reject(contributionNotOnlyFee(), false, 1, 2_000L, null),
                () -> reject(contributionPaysMoreThanAddedInputs(), false, 1, 7_000L, null),
                () -> reject(disallowedSubstitution(), false, null, null, null),
                () -> reject(outputDecreased(), false, null, null, null),
                () -> reject(missingOutput(), false, null, null, null),
                () -> reject(absoluteFeeDecreased(), false, null, null, null),
                () -> reject(feeRateBelowMinimum(), false, null, null, 1_000_000L),
                () -> reject(unsupportedAddedInput(), false, null, null, null));
    }

    @Test
    void rejectsAHostileProposalAndABadOriginal() {
        TestPsbt original = TestPsbt.funded(payee);
        assertThrows(
                CounterpartyException.class,
                () -> Checklist.accept(encode(original), new byte[] {1, 2, 3}, payee, false, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> Checklist.vetOriginal(encode(original), TestPsbt.p2wpkh(0x99), null));
        assertThrows(IllegalArgumentException.class, () -> Checklist.vetOriginal(encode(original), payee, 1L));
        TestPsbt sighash = original.copy();
        sighash.inputs.get(0).sighash = 2;
        assertThrows(IllegalArgumentException.class, () -> Checklist.vetOriginal(encode(sighash), payee, null));
        Checklist.vetOriginal(encode(original), payee, 50_000L);
    }

    @Test
    void readsTheValueFromThePreviousTransaction() throws Exception {
        byte[] previous = previousTransaction(100_000, TestPsbt.p2wpkh(0x11));
        byte[] txid = MessageDigest.getInstance("SHA-256").digest(MessageDigest.getInstance("SHA-256").digest(previous));
        TestPsbt original = TestPsbt.funded(payee);
        TestPsbt.In input = original.inputs.get(0);
        input.txid = txid;
        input.witnessValue = null;
        input.witnessScript = null;
        input.nonWitness = previous;
        Checklist.vetOriginal(encode(original), payee, 50_000L);
        Checklist.accept(encode(original), original.bytes(), payee, false, null, null, null);
    }

    @Test
    void decodesPaymentScripts() {
        assertArrayEquals(
                hex("0014751e76e8199196d454941c45d1b3a323f1433bd6"),
                AddressScript.script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assertArrayEquals(
                hex("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                AddressScript.script("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"));
        assertArrayEquals(
                hex("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
                AddressScript.script("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
        assertThrows(IllegalArgumentException.class, () -> AddressScript.script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));
        assertThrows(IllegalArgumentException.class, () -> AddressScript.script("not an address"));
    }

    private void accept(TestPsbt proposal, boolean substitution, Integer feeIndex, Long feeSats, Long minFee) {
        Checklist.accept(encode(TestPsbt.funded(payee)), proposal.bytes(), payee, substitution, feeIndex, feeSats, minFee);
    }

    private void reject(TestPsbt proposal, boolean substitution, Integer feeIndex, Long feeSats, Long minFee) {
        assertThrows(
                CounterpartyException.class,
                () -> Checklist.accept(encode(TestPsbt.funded(payee)), proposal.bytes(), payee, substitution, feeIndex, feeSats, minFee));
    }

    private static String encode(TestPsbt psbt) {
        return Base64.getEncoder().encodeToString(psbt.bytes());
    }

    private TestPsbt version() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.version = 1;
        return proposal;
    }

    private TestPsbt locktime() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.locktime = 1;
        return proposal;
    }

    private TestPsbt inputKeyPath() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.get(0).bip32 = true;
        return proposal;
    }

    private TestPsbt partialSignature() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.get(0).partial = true;
        return proposal;
    }

    private TestPsbt senderSequence() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.get(0).sequence = 1;
        return proposal;
    }

    private TestPsbt senderScript() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.get(0).finalScriptSig = new byte[] {0x51};
        return proposal;
    }

    private TestPsbt senderWitness() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.get(0).finalWitness = new byte[][] {new byte[] {1}};
        return proposal;
    }

    private TestPsbt sighash() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.get(0).sighash = 0x83;
        return proposal;
    }

    private TestPsbt receiverNotFinalized() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.add(TestPsbt.In.witness(TestPsbt.bytes(0x44, 32), 0, 0xfffffffe, 10_000, TestPsbt.p2wpkh(0x44)));
        return proposal;
    }

    private TestPsbt receiverMissingOutput() {
        TestPsbt proposal = TestPsbt.funded(payee);
        TestPsbt.In input = finalized(TestPsbt.bytes(0x44, 32), 10_000, TestPsbt.p2wpkh(0x44));
        input.witnessValue = null;
        input.witnessScript = null;
        proposal.inputs.add(input);
        return proposal;
    }

    private TestPsbt mixedSequence() {
        TestPsbt proposal = TestPsbt.funded(payee);
        TestPsbt.In input = finalized(TestPsbt.bytes(0x44, 32), 10_000, TestPsbt.p2wpkh(0x44));
        input.sequence = 1;
        proposal.inputs.add(input);
        return proposal;
    }

    private TestPsbt missingInput() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.clear();
        proposal.inputs.add(finalized(TestPsbt.bytes(0x44, 32), 100_000, TestPsbt.p2wpkh(0x44)));
        return proposal;
    }

    private TestPsbt outputKeyPath() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.outputs.get(0).bip32 = true;
        return proposal;
    }

    private TestPsbt contributionExceedsMaximum() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.outputs.get(1).value -= 100;
        return proposal;
    }

    private TestPsbt contributionNotOnlyFee() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.add(finalized(TestPsbt.bytes(0x44, 32), 5_000, TestPsbt.p2wpkh(0x44)));
        proposal.outputs.get(1).value -= 1_000;
        proposal.outputs.add(new TestPsbt.Out(5_500, TestPsbt.p2wpkh(0x66)));
        return proposal;
    }

    private TestPsbt contributionPaysMoreThanAddedInputs() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.add(finalized(TestPsbt.bytes(0x44, 32), 10_000, TestPsbt.p2wpkh(0x44)));
        proposal.outputs.get(1).value -= 7_000;
        return proposal;
    }

    private TestPsbt disallowedSubstitution() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.outputs.get(0).script = TestPsbt.p2wpkh(0x55);
        return proposal;
    }

    private TestPsbt outputDecreased() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.outputs.get(1).value -= 1;
        return proposal;
    }

    private TestPsbt missingOutput() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.outputs.remove(1);
        return proposal;
    }

    private TestPsbt absoluteFeeDecreased() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.outputs.get(0).value += 1_000;
        return proposal;
    }

    private TestPsbt feeRateBelowMinimum() {
        return TestPsbt.funded(payee);
    }

    private TestPsbt unsupportedAddedInput() {
        TestPsbt proposal = TestPsbt.funded(payee);
        proposal.inputs.add(finalized(TestPsbt.bytes(0x44, 32), 10_000, new byte[] {0x6a}));
        return proposal;
    }

    private static TestPsbt.In finalized(byte[] txid, long value, byte[] script) {
        TestPsbt.In input = TestPsbt.In.witness(txid, 0, 0xfffffffe, value, script);
        input.finalWitness = new byte[][] {new byte[] {1}};
        return input;
    }

    private static byte[] previousTransaction(long value, byte[] script) {
        java.io.ByteArrayOutputStream raw = new java.io.ByteArrayOutputStream();
        TestPsbt.writeU32(raw, 1);
        TestPsbt.writeCompact(raw, 1);
        raw.writeBytes(TestPsbt.bytes(0x22, 32));
        TestPsbt.writeU32(raw, 0);
        TestPsbt.writeCompact(raw, 0);
        TestPsbt.writeU32(raw, 0xffffffff);
        TestPsbt.writeCompact(raw, 1);
        TestPsbt.writeU64(raw, value);
        TestPsbt.writeCompact(raw, script.length);
        raw.writeBytes(script);
        TestPsbt.writeU32(raw, 0);
        return raw.toByteArray();
    }

    private static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
