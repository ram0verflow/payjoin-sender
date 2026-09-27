# 0009. Fragment parameters and OHTTP key id

Status: Accepted
Date: 2026-09-24

## Context

BIP 77's specification section, changelog 0.2.0, and example URI order
fragment parameters lexicographically (`EX`, `OH`, `RK`). The rationale
still says reverse lexicographical order. rust-payjoin emits
lexicographical order, accepts any order, and accepts `+` only when `-`
is absent.

The specification calls the `OH` key identifier two bytes. The example
and rust-payjoin use one byte, then a 33-byte compressed gateway key
(34 bytes total), matching the RFC 9458 key identifier.

## Decision

Emit `EX-OH-RK` separated by `-`. Accept any order. Accept `+` only when
`-` is absent. Reject a mix of `+` and `-`, and reject any lowercase
fragment character. Decode `OH` as one key-id byte plus 33 compressed
public-key bytes, then rebuild the RFC 9458 key config with KEM
`0x0016`, KDF `0x0001`, and AEAD `0x0003`.

## Consequences

URIs match rust-payjoin and the BIP example. They do not follow the
rationale's reverse-order sentence or the "2-byte" key-id sentence.
