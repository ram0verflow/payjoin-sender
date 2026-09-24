# 0008. Test oracle

Status: Accepted
Date: 2026-09-24

## Context

Differential tests need byte-identical output from rust-payjoin.
payjoin-ffi already exposes that library to the JVM. The project rule
is that Rust appears only in tests.

## Decision

Tests may depend on a locally built payjoin-ffi Kotlin jar and its
native library. That dependency is test-scoped and is never on the main
compile classpath. Published specification vectors are still required
for each primitive.

## Consequences

Test runs that use the oracle need a native library built from
rust-payjoin. The published jar of this library stays pure Java.
