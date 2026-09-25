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

Use Bouncy Castle for secp256k1 and HKDF-SHA256. Implement
ElligatorSwift in this project and test it against the BIP 324 vectors.
Use the JDK `ChaCha20-Poly1305` cipher and `SecureRandom`. Tests inject
randomness.

ADR 0011 records the Bouncy Castle artifact. ADR 0012 replaces the
earlier plan to subclass Bouncy Castle's HPKE framework: that KEM type
is not visible outside its package, so the RFC 9180 key schedule is
local code.

## Consequences

The curve implementation is Bouncy Castle's, which is not the
constant-time implementation in libsecp256k1. ElligatorSwift and the
HPKE key schedule are code this project maintains. No JNI library is
shipped.
