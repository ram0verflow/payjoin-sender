# 0001. Project identity

Status: Accepted
Date: 2026-09-24

## Context

The library is a standalone pure-Java BIP 77 sender. It is not a
binding to rust-payjoin.

## Decision

The project is `payjoin-sender`, group `dev.ramoverflow.payjoin`,
base package `dev.ramoverflow.payjoin.sender`, licensed under
Apache-2.0.

## Consequences

Consumers depend on `dev.ramoverflow.payjoin:payjoin-sender`. The
license matches a common choice for JVM Bitcoin libraries. It differs
from rust-payjoin's `MITNFA` crates.
