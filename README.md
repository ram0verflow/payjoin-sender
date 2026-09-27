# payjoin-sender

A pure-Java sender for [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.mediawiki) (Async Payjoin).

**Experimental. The cryptography is unaudited. Do not use it with real funds. Test on regtest or signet only.**

The library builds protocol messages and checks the receiver's proposal. The caller supplies HTTP, the clock, randomness, storage, and the wallet's original PSBT. No native code is shipped.

Java 17 or newer. Maven coordinates `dev.ramoverflow.payjoin:payjoin-sender:0.1.0-SNAPSHOT`. JPMS module `dev.ramoverflow.payjoin.sender`. Apache-2.0.

## Install

This repository is the source. The artifact is not on Maven Central.

```sh
./gradlew test
```

Bouncy Castle `bcprov-jdk18on` 1.80 is the only runtime dependency. On the module path, require `dev.ramoverflow.payjoin.sender`.

## Usage

`Sender.start` opens a session. Each step returns a `Request`. The caller POSTs that request to an OHTTP relay and passes the HTTP status and body back to `resume`. The outer method is always POST, with `Content-Type: message/ohttp-req`.

```java
import dev.ramoverflow.payjoin.sender.Options;
import dev.ramoverflow.payjoin.sender.Persister;
import dev.ramoverflow.payjoin.sender.Poll;
import dev.ramoverflow.payjoin.sender.Post;
import dev.ramoverflow.payjoin.sender.Proposal;
import dev.ramoverflow.payjoin.sender.Request;
import dev.ramoverflow.payjoin.sender.Sender;
import dev.ramoverflow.payjoin.sender.Session;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

Persister log = new Persister() {
    private final List<String> lines = new ArrayList<>();

    public void append(String line) {
        lines.add(line);
    }

    public List<String> load() {
        return List.copyOf(lines);
    }
};

Post post = Sender.start(
        payjoinUri,
        originalPsbtBase64,
        Options.none(),
        Clock.systemUTC(),
        new SecureRandom(),
        log);
Request posted = post.request(relayUrl);
byte[] response = httpPost(posted.url(), Request.CONTENT_TYPE, posted.body());
Poll poll = post.resume(200, response);

Session step = poll;
while (step instanceof Poll waiting) {
    Request next = waiting.request(relayUrl);
    response = httpPost(next.url(), Request.CONTENT_TYPE, next.body());
    step = waiting.resume(200, response);
}
String proposalPsbt = ((Proposal) step).psbt();
```

`proposalPsbt` is the receiver's PSBT with padding removed. The sender checklist has already passed. Wallet metadata from the original PSBT is not copied back; the caller restores that.

`Options` can set a maximum fee contribution in satoshis, the output index that receives it, a minimum fee rate in satoshis per virtual byte, and whether to disable output substitution.

## Persistence and resume

`Persister` is an append-only log. Each `append` string is one JSON object and does not include a newline. `load` returns those strings in order.

`Sender.resume(log, clock, random)` restores the session:

- a log that ends at `created` returns a post step
- a log that includes `posted` returns a poll step
- a successful close returns the `Proposal` only after the checklist passes again

A crash after the caller has sent the POST, and before that response was resumed, is at-least-once. Resume returns a post step, and the next `request` builds a new ciphertext. It does not retry the ciphertext that was already sent.

OHTTP ciphertext, the response context, and the relay URL are not stored. The relay URL is an argument of `request` and can change between calls.

## Security

The log contains the reply key and the original PSBT. The caller protects it at rest. This library does not encrypt it.

Treat the receiver, the directory, and the relay as hostile. A proposal is accepted only after the sender checklist. Receiver error text copied into an exception is reduced to printable ASCII.

The cryptography has not been audited. Use regtest or signet.

## Interoperability tests

`./gradlew test` does not need Rust.

`./gradlew oracleTest` cross-checks this library against [rust-payjoin](https://github.com/payjoin/rust-payjoin). By default it looks for that checkout at `../rust-payjoin`. Another path is `-PpayjoinOracle=/path/to/rust-payjoin`. The URI comparison needs the `payjoin-ffi` library built in that checkout. A session test can run a payjoin-cli receiver on regtest when that toolchain is present.

## BIP 77

Two sentences in BIP 77 disagree with the example and with rust-payjoin. This library follows the example and rust-payjoin.

**Fragment order.** The specification, the 0.2.0 changelog, and the example URI order fragment parameters lexicographically (`EX`, `OH`, `RK`). The rationale still says reverse lexicographical order. Parsed URIs are emitted as `EX-OH-RK` separated by `-`. Any input order is accepted. `+` is accepted only when `-` is absent. A mix of the two separators is rejected, as is any lowercase fragment character.

**OHTTP key id.** The specification calls the `OH` key identifier two bytes. The example and rust-payjoin use one byte, then a 33-byte compressed gateway key (34 bytes total), matching the RFC 9458 key identifier. `OH` is decoded that way, and the RFC 9458 key config is rebuilt with KEM `0x0016`, KDF `0x0001`, and AEAD `0x0003`.

## License

[Apache-2.0](LICENSE).

## Acknowledgements

Thanks to the [Payjoin](https://payjoin.org) project, the authors of BIP 77 and BIP 78, and the rust-payjoin contributors. The interoperability tests use rust-payjoin as the reference implementation.
