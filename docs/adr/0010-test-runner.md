# 0010. Test runner

Status: Accepted
Date: 2026-09-24

## Context

Every change needs tests, including failure cases. The scaffold had no
test classes, so the test task had nothing to run.

## Decision

Tests use JUnit Jupiter 5.12.2 and the JUnit Platform launcher.
Both are test dependencies only.

## Consequences

`./gradlew test` runs the JUnit platform. A different runner would be a
new decision.
