# 0004. Cryptography

Status: Accepted
Date: 2026-09-24

## Context

The JDK provides ChaCha20-Poly1305 and SecureRandom. It does not
provide secp256k1, ElligatorSwift, or DHKEM(secp256k1). BIP 77 forbids
shipping a native library in this artifact. Bouncy Castle can supply
the curve, HKDF, and an HPKE framework that accepts a custom KEM.
ElligatorSwift has published BIP 324 vectors and no small standalone
Java library.

## Decision

Use Bouncy Castle for secp256k1, HKDF-SHA256, and the HPKE framework,
with a custom secp256k1 KEM. Implement ElligatorSwift in this project
and test it against the BIP 324 vectors. Use the JDK
`ChaCha20-Poly1305` cipher and `SecureRandom`. Tests inject randomness.
The Bouncy Castle dependency is added when the first crypto code needs
it, not before.

## Consequences

The curve implementation is Bouncy Castle's, which is not the
constant-time implementation in libsecp256k1. ElligatorSwift and the
secp256k1 KEM are code this project maintains. No JNI library is shipped.
