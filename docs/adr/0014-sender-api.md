# 0014. Sender session API

Status: Accepted
Date: 2026-09-27

## Context

ADR 0005 takes PSBTs as base64. ADR 0006 does no HTTP: a step returns a
URL, method, and body, and the next step accepts a status and a body.
ADR 0013 takes the OHTTP key from the URI. The relay URL is chosen by
the caller and can change between requests. Expiration and key
generation must be testable without the wall clock or a shared
`SecureRandom`.

## Decision

`Sender.start(uri, originalPsbtBase64, options, clock, random)` returns
a post step. `options` carries the BIP 78 sender parameters: maximum
fee contribution in satoshis, fee output index, minimum fee rate in
satoshis per virtual byte, and whether to disable output substitution.
`clock` is `java.time.Clock`. `random` supplies the reply key and the
OHTTP randomness.

The relay URL is an argument of `request()`, not of `start()`, and it
is not persisted. `request()` returns the URL, method, and body. The
POST body is single-use. `resume(status, body)` on the post step
returns a poll step. `resume(status, body)` on the poll step returns
the same poll step while the directory status is 202 and the URI expiry
has not passed, and returns the Proposal PSBT base64 when the proposal
arrives. A 202 after expiry fails as expired.

Once the BIP 78 sender checklist lands, `resume` returns that Proposal
PSBT only after the checklist passes. Until then, a proposal is not
offered as ready to sign.

## Consequences

Callers perform every POST and GET, and they may switch relays between
polls. HPKE, OHTTP, and the reply key stay inside the session. The
checklist is a later phase; this API does not skip it.
