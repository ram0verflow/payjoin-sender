# 0005. PSBT boundary

Status: Accepted
Date: 2026-09-24

## Context

The BIP 78 sender checklist inspects inputs, outputs, sequences, fees,
sighash types, and final scripts. Callers such as Sparrow already have
their own PSBT type and restore wallet metadata themselves.

## Decision

This library accepts and returns PSBT v0 as base64 strings. It contains
the minimum parser the checklist needs. It does not depend on a wallet
PSBT type.

## Consequences

Callers serialize before calling in and parse the returned string. A
small PSBT parser lives in this repository. bitcoinj is not a dependency.
