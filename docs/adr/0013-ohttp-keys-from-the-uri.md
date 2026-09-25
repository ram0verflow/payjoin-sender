# 0013. OHTTP keys come from the URI

Status: Accepted
Date: 2026-09-25

## Context

RFC 9458 key configuration can also be fetched from a gateway, and
RFC 9540 describes that application intermediation, including the
well-known gateway path. BIP 77 puts the receiver's OHTTP key in the
URI fragment. The sender already has to parse that fragment before it
can encapsulate anything.

## Decision

The sender does not fetch an OHTTP key configuration. It rebuilds the
key config from the 34-byte OH parameter. A relay URL is passed in by
the caller. Tests that talk to a local directory may fetch keys out of
band; that fetch is not a library API.

## Consequences

There is no HTTP client for key discovery in this package. A sender
cannot speak to a directory whose key was not in the Payjoin URI.
