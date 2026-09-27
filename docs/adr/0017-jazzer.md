# 0017. Fuzzing

Status: Accepted
Date: 2026-09-27

## Context

The sender parses hostile bytes in six places: the Payjoin URI, an
OHTTP response, Binary HTTP, Message B, a PSBT, and a session log
line. ADR 0010 keeps JUnit Jupiter as the test runner. A fuzzer is an
extra test dependency, not a replacement for that runner.

## Decision

The fuzzer is Jazzer, `com.code-intelligence:jazzer-junit:0.30.0`,
test scope only. It is not on the runtime classpath of the published
jar, and its native agent is not shipped.

`./gradlew fuzz` is the only task that runs it. The task sets
`JAZZER_FUZZ=1`, instruments `org.payjoin.sender.**`, and forks once
per class. libFuzzer runs one target per process, so each parser is
its own test class. Each target is bounded to 30 seconds.
`./gradlew test` excludes the `fuzz` tag, so it does not replay the
corpus and does not start the fuzzer.

The six targets are `PayjoinUri.parse` (then the address script),
`Ohttp.decapsulate`, `Bhttp.response`, `Messages.decryptB` then
`PsbtBytes.proposal`, `Psbt.read` and `PsbtBytes.proposal`, and
`EventLog.parse`. Expected parse failures are caught. A thrown
message that contains the fixed test reply key fails the run, unless
those characters were already in the input.

## Consequences

`./gradlew test` stays the default check and does not need the fuzzer
to finish. `./gradlew fuzz` is the coverage-guided run. A different
fuzzer, or running Jazzer from the test task, would be a new
decision.
