# 0016. Session log codec

Status: Accepted
Date: 2026-09-27

## Context

ADR 0015 stores the session as version-1 JSON, one object per line.
The log holds the reply key. Java 17 has no JSON parser in the
platform. A general library is more surface than four fixed objects.
A hand-written parser is accepted only if it is strict.

## Decision

The codec lives inside the session package and is not part of the
public API. It reads and writes only the version-1 events.

Parsing rejects duplicate keys, unknown keys, missing required keys,
trailing data after the object, and nesting deeper than one object.
Numbers are integers only: no fraction, no exponent, no leading zeros.
Strings contain no escape sequences. The other allowed value is a
boolean. Raw control characters and non-ASCII bytes are rejected. A
line longer than 65536 bytes is rejected.

The writer emits those values without escape sequences. The result is
ordinary JSON that a standard parser can read. A JSON library is not
added, including in tests, unless a later ADR allows it.

Tests round-trip each of the four events and reject malformed,
truncated, oversized, and duplicate-key input.

## Consequences

A corrupted or hostile log fails before it can allocate an unbounded
string. The reply key is still plaintext in the file. Callers protect
the log at rest, as ADR 0015 requires.
