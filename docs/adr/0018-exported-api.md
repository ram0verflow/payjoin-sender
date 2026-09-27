# 0018. Exported API

Status: Accepted
Date: 2026-09-27

## Context

The module compiled with every package exported. Callers of ADR 0014
only need the session types and a Payjoin URI. Crypto, OHTTP, the
fragment codec, and the mailbox short-id type are implementation
details. JPMS exports packages, so a public class in an exported
package stays reachable.

## Decision

The module exports `dev.ramoverflow.payjoin.sender` and
`dev.ramoverflow.payjoin.sender.uri`.
`dev.ramoverflow.payjoin.sender.crypto` and
`dev.ramoverflow.payjoin.sender.ohttp` are not
exported. Their package docs say they are internal. Classes there stay
public so the rest of this module can call them.

In `dev.ramoverflow.payjoin.sender.uri`, the public types are
`PayjoinUri` and `UriParseException`. `Bech32` and `ShortId` are
package-private.
`PayjoinUri.shortId()` returns the mailbox id as a string.
`PayjoinUri.shortIdOf` does the same for a compressed secp256k1 key,
which is how the session names a reply key.

## Consequences

Another module cannot call HPKE, OHTTP, or the fragment codec. The
session types in ADR 0014 remain the caller surface, plus `PayjoinUri`
and `UriParseException`. Moving any of the hidden types back into the
export would be a new decision.
