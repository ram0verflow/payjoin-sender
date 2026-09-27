package dev.ramoverflow.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Full sender session against payjoin-cli on regtest. Not part of {@code test}.
 * The proposal is a rust-payjoin Message B, ElligatorSwift prefix included.
 * It is returned only after the sender checklist accepts it.
 */
@Tag("oracle")
/** Regtest only. Keys are created for this test and are not wallets. */
class SessionOracleTest {
    @Test
    @Timeout(value = 20, unit = TimeUnit.MINUTES)
    void completesASessionAndResumesFromTheLog() throws Exception {
        Path cli = Path.of("../rust-payjoin/target/debug/payjoin-cli");
        ProcessBuilder build = new ProcessBuilder(
                "cargo", "build", "-p", "payjoin-cli", "--features", "_manual-tls",
                "--manifest-path", "../rust-payjoin/Cargo.toml");
        build.redirectError(ProcessBuilder.Redirect.INHERIT);
        build.redirectOutput(ProcessBuilder.Redirect.INHERIT);
        assertEquals(0, build.start().waitFor());

        ProcessBuilder harnessBuilder = new ProcessBuilder(
                "cargo", "run", "--quiet", "--locked", "--manifest-path",
                "src/test/rust/session-oracle/Cargo.toml");
        harnessBuilder.redirectError(ProcessBuilder.Redirect.INHERIT);
        harnessBuilder.environment().put("PAYJOIN_CLI", cli.toAbsolutePath().toString());
        Process harness = harnessBuilder.start();
        try {
            BufferedReader lines = new BufferedReader(new InputStreamReader(harness.getInputStream(), StandardCharsets.US_ASCII));
            String bip21 = value(lines.readLine(), "BIP21");
            String relay = value(lines.readLine(), "RELAY");
            String psbt = value(lines.readLine(), "PSBT");
            assertEquals("READY", lines.readLine());

            InMemoryPersister log = new InMemoryPersister();
            Clock clock = Clock.systemUTC();
            Post post = Sender.start(bip21, psbt, Options.none(), clock, new SecureRandom(), log);
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            dev.ramoverflow.payjoin.sender.Request request = post.request(relay);
            HttpResponse<byte[]> response = send(http, request);
            post.resume(response.statusCode(), response.body());
            Poll poll = assertInstanceOf(Poll.class, Sender.resume(log, clock, new SecureRandom()));

            Proposal proposal = null;
            Session step = poll;
            for (int attempt = 0; attempt < 20 && proposal == null; attempt++) {
                request = ((Poll) step).request(relay);
                response = send(http, request);
                step = ((Poll) step).resume(response.statusCode(), response.body());
                if (step instanceof Proposal done) {
                    proposal = done;
                }
            }
            assertNotNull(proposal, "directory did not return a proposal");
            assertTrue(proposal.psbt().startsWith("cHNidP"));
            Proposal restored = assertInstanceOf(Proposal.class, Sender.resume(log, clock, new SecureRandom()));
            assertEquals(proposal.psbt(), restored.psbt());
        } finally {
            harness.getOutputStream().close();
            if (!harness.waitFor(2, TimeUnit.MINUTES)) {
                harness.destroyForcibly();
            }
        }
        assertEquals(0, harness.exitValue());
    }

    private static HttpResponse<byte[]> send(HttpClient http, dev.ramoverflow.payjoin.sender.Request request) throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(request.url()))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", dev.ramoverflow.payjoin.sender.Request.CONTENT_TYPE)
                .POST(HttpRequest.BodyPublishers.ofByteArray(request.body()))
                .build();
        return http.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
    }

    private static String value(String line, String key) {
        String prefix = key + "=";
        assertNotNull(line, key);
        assertTrue(line.startsWith(prefix), line);
        return line.substring(prefix.length());
    }
}
