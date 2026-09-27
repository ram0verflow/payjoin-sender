# 0002. Build tool and minimum Java

Status: Accepted
Date: 2026-09-24

## Context

Callers run on current JDKs and use JPMS. This library must stay
usable from that runtime without requiring Java 25 language features.

## Decision

One Gradle build. Source and target release are Java 17. The main
sources are a JPMS module named `dev.ramoverflow.payjoin.sender`.

## Consequences

The build runs on newer JDKs with `--release 17`. Java 11 consumers
cannot use the library. A formatter or linter plugin is not part of
this decision.
