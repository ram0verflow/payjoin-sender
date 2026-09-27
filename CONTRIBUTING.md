# Contributing

Java 17 or newer. Use the Gradle wrapper.

```sh
./gradlew test
```

runs the default tests. It does not need a Rust toolchain, and it does
not run the fuzzer.

```sh
./gradlew oracleTest
```

cross-checks this library against rust-payjoin. It needs Cargo and a
checkout of that repository, by default at `../rust-payjoin`. Pass
`-PpayjoinOracle=/path/to/rust-payjoin` for another checkout. The URI
comparison needs `payjoin-ffi` built in that checkout.

```sh
./gradlew fuzz
```

runs Jazzer for 30 seconds on each parser. It is not part of `test`.

Decisions are in `docs/adr/`. Match the style of the surrounding code.
