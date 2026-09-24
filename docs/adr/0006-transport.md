# 0006. Transport

Status: Accepted
Date: 2026-09-24

## Context

The reference sender returns a request and consumes a response. OHTTP
ciphertext must not be retried. Wallets already have an HTTP client,
often with a Tor proxy.

## Decision

The library performs no HTTP. A session step returns a URL, a method,
and a body, and the next step accepts a status code and a body.

## Consequences

There is no `java.net.http` dependency. Callers, including tests, perform
the POST and the poll. A demo that speaks to a relay must bring its own
client.
