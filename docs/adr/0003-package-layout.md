# 0003. Package layout

Status: Accepted
Date: 2026-09-24

## Context

The sender, URI parsing, OHTTP, and cryptography are separate concerns
inside one artifact.

## Decision

One Gradle project. Four packages, with dependencies pointing downward
only:

- `dev.ramoverflow.payjoin.sender` depends on the three below
- `dev.ramoverflow.payjoin.sender.ohttp` may depend on `crypto`
- `dev.ramoverflow.payjoin.sender.uri` may depend on `crypto`
- `dev.ramoverflow.payjoin.sender.crypto` depends on neither

The test oracle and regtest harness stay out of `src/main`.

## Consequences

Publishing is one artifact. Splitting a package into its own project
later does not require a package rename. The downward rule is review,
not a Gradle project boundary.
