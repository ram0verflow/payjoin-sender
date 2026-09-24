# payjoin-sender

Pure-Java sender for [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md) (Async Payjoin).

The library builds protocol messages and checks proposals. The caller supplies HTTP, time, randomness, storage, and the wallet's PSBT type. No native code is shipped.

Group: `org.payjoin`. Minimum Java: 17. License: Apache-2.0.

```sh
./gradlew test
```

Accepted decisions are in `docs/adr/`.
