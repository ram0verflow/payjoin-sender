# 0012. Local HPKE key schedule

Status: Accepted
Date: 2026-09-25

## Context

ADR 0004 planned to subclass Bouncy Castle's HPKE framework with a
custom secp256k1 KEM. `org.bouncycastle.crypto.hpke.KEM` has no public
constructor and is not visible outside its package, so that hook cannot
be used. BIP 77 still needs DHKEM(secp256k1, HKDF-SHA256) with
ChaCha20-Poly1305, KEM id `0x0016`. Writing the key schedule here is a
hand-implemented primitive and needed owner approval.

## Decision

Implement the RFC 9180 key schedule in `org.payjoin.sender.crypto.Hpke`.
Bouncy Castle supplies the curve and HKDF. The JDK supplies
ChaCha20-Poly1305. `LabeledExpand` follows RFC 9180: the info string
starts with `I2OSP(L, 2)`.

Cross-checks against bitcoin-hpke 0.13.0 run from a Cargo harness under
`src/test/rust/hpke-oracle`. That crate is a test tool. It is not a
library dependency, and no Rust file is in a main source set. The
harness checks the sender's directions at protocol size: Java seals
Base and bitcoin-hpke opens it; bitcoin-hpke seals Auth and Java opens
it. A tampered ciphertext must fail in each direction.

## Consequences

This project maintains the key schedule, including the secp256k1
`DeriveKeyPair` and the base and auth DH concatenations. Published
draft vectors stay mandatory. The bitcoin-hpke harness is optional only
in the sense that `cargo` must be on the path for that test; the test
fails when the harness cannot run.
