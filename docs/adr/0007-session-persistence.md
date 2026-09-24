# 0007. Session persistence

Status: Accepted
Date: 2026-09-24

## Context

rust-payjoin persists an append-only event log and replays it.
payjoin-cli stores that log as JSON in SQLite. That encoding is not a
library format. The log holds the reply private key and the original
PSBT.

## Decision

The library defines the session events and a persister interface. It
does not define an on-disk byte format. Tests use an in-memory
persister.

## Consequences

Callers choose storage. Two applications cannot exchange session files
until a versioned format is accepted in a later ADR.
