# 0011. Bouncy Castle dependency

Status: Accepted
Date: 2026-09-25

## Context

ADR 0004 chose Bouncy Castle for secp256k1 and HKDF-SHA256. The first
crypto code needs that library on the compile classpath. No other
Java library in this project provides the curve.

## Decision

Depend on `org.bouncycastle:bcprov-jdk18on:1.80` as an implementation
dependency. The module requires `org.bouncycastle.provider`.

## Consequences

The published jar is pure Java and links Bouncy Castle. A version bump
is a dependency change and needs the lockfiles updated the same way as
any other dependency. HKDF and secp256k1 arithmetic go through this
artifact. ChaCha20-Poly1305 stays on the JDK cipher.
