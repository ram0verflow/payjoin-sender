# 0001. Project identity

Status: Accepted
Date: 2026-09-24

## Context

The library is a standalone pure-Java BIP 77 sender. It is not part of
Sparrow and not a binding to rust-payjoin. Name, Maven coordinates, and
license are public once the first artifact exists.

## Decision

The project is `payjoin-sender`, group `org.payjoin`, base package
`org.payjoin.sender`, licensed under Apache-2.0.

## Consequences

Consumers depend on `org.payjoin:payjoin-sender`. The license matches a
common choice for JVM Bitcoin libraries. It differs from rust-payjoin's
`MITNFA` crates.
