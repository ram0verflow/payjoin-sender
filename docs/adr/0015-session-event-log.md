# 0015. Session event log

Status: Accepted
Date: 2026-09-27

## Context

ADR 0007 defines session events and a persister interface, and leaves
the byte format open. An interrupted send has to resume on another
process. rust-payjoin does that by replaying an append-only log.

## Decision

The log is versioned JSON, schema version 1, one JSON object per line.
Each object has `v` and a type: `created`, `posted`, `cancelled`, or
`closed`. `created` holds the reply key, the Original PSBT, the
endpoint, the expiry, the 34-byte OHTTP key, the receiver key, and the
output-substitution flag, plus the fee parameters from ADR 0014.
`closed` holds the outcome and, on success, the Proposal PSBT. An
unknown `v` is rejected. Replay restores the session.

The persister receives secret material: the reply key and the Original
PSBT. The caller protects the log at rest. This library does not
encrypt it.

The OHTTP request ciphertext and its response context are not in the
log. Delivery of the original POST is at-least-once: a crash after the
body is sent and before `resume` accepts the response does not retry
that ciphertext, and it does not record `posted`. The caller sends a
new POST from `created`. Resume from `posted` polls.

The relay URL is not stored.

How the JSON is read and written is a separate decision. No JSON
library and no hand-written parser are added under this ADR.

## Consequences

Tests use an in-memory persister that records these events. A stored
log from a newer schema does not load as version 1. Callers who copy
the file between machines are copying the reply key.
