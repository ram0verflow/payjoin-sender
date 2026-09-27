# 0005. PSBT boundary

Status: Accepted
Date: 2026-09-24

## Context

The BIP 78 sender checklist inspects inputs, outputs, sequences, fees,
sighash types, and final scripts. Callers already have their own
PSBT type and restore wallet metadata themselves.

## Decision

This library accepts and returns PSBT v0 as base64 strings. It contains
the minimum parser the checklist needs. It does not depend on a wallet
PSBT type.

The checklist follows rust-payjoin, including the sighash rule and the
per-input weight estimate. That differs from the BIP 78 text in two
places. BIP 78 does not mention sighash types; rust-payjoin rejects a
sender input whose sighash does not commit to every input and output.
BIP 78 prices added inputs as the sender input's virtual size times
the count of added inputs; rust-payjoin sums a per-input weight for
each proposal input whose script is not one of the original scripts.

The reader treats the proposal as hostile input. It rejects duplicate
keys, malformed lengths, and anything truncated or oversized.

The returned proposal is the receiver's PSBT with padding removed.
Wallet metadata is not copied back into it.

## Consequences

Callers serialize before calling in and parse the returned string.
A small PSBT parser lives in this repository. bitcoinj is not a
dependency.
Callers restore wallet metadata themselves. The created session event
records the payee script from the URI address so the checklist can run
when the proposal arrives, including after resume.
