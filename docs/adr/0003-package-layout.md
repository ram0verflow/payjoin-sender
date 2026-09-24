# 0003. Package layout

Status: Accepted
Date: 2026-09-24

## Context

The sender, URI parsing, OHTTP, and cryptography are separate concerns.
No second consumer has asked to depend on one of them alone.

## Decision

One Gradle project. Four packages, with dependencies pointing downward
only:

- `org.payjoin.sender` depends on the three below
- `org.payjoin.sender.ohttp` may depend on `crypto`
- `org.payjoin.sender.uri` may depend on `crypto`
- `org.payjoin.sender.crypto` depends on neither

The test oracle and regtest harness stay out of `src/main`.

## Consequences

Publishing is one artifact. Splitting a package into its own project
later does not require a package rename. The downward rule is review,
not a Gradle project boundary.
