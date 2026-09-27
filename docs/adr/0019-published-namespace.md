# 0019. Published namespace

Status: Accepted
Date: 2026-09-27

## Context

This library is not an artifact of the Payjoin project. Coordinates
under `org.payjoin` would look like that project's own publication.

## Decision

The Gradle group is `dev.ramoverflow.payjoin`. The JPMS module and the
base package are `dev.ramoverflow.payjoin.sender`. Those are the
coordinates in ADR 0001.

## Consequences

Consumers depend on
`dev.ramoverflow.payjoin:payjoin-sender`. A module
path user requires `dev.ramoverflow.payjoin.sender`.
