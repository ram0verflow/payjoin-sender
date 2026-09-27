package dev.ramoverflow.payjoin.sender.ohttp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Cross-checks that need the OHTTP crate and a local directory. Not part of {@code test}. */
@Tag("oracle")
/** Test-only keys, checked against bitcoin-ohttp. Do not use them as wallets. */
class OhttpOracleTest {
    private static final Path CRATE = Path.of("src/test/rust/ohttp-oracle");
    private static final Path DIRECTORY = Path.of("src/test/rust/directory-oracle");

    @Test
    void bitcoinOhttpOpensJavaRequestAndJavaOpensItsResponse() throws Exception {
        Process process = new ProcessBuilder("cargo", "run", "--quiet", "--locked", "--manifest-path",
                CRATE.resolve("Cargo.toml").toString())
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try {
            InputStream stdout = process.getInputStream();
            byte[] compressed = stdout.readNBytes(34);
            assertEquals(34, compressed.length);
            OhttpKeys keys = OhttpKeys.parse(compressed);
            byte[] body = new byte[] {1, 2, 3};
            Ohttp.Request request = Ohttp.encapsulate(
                    keys, "POST", "https://payjo.in/TXJCGKTKXLUUZ", body, new Random(4));
            OutputStream stdin = process.getOutputStream();
            stdin.write(request.encapsulated());
            stdin.close();
            int plaintextLength = readInt(stdout);
            byte[] plaintext = stdout.readNBytes(plaintextLength);
            byte[] expected = Bhttp.request("POST", "https", "payjo.in", "/TXJCGKTKXLUUZ", body);
            assertArrayEquals(expected, java.util.Arrays.copyOf(plaintext, expected.length));
            byte[] response = stdout.readNBytes(Ohttp.ENCAPSULATED_LEN);
            assertEquals(Ohttp.ENCAPSULATED_LEN, response.length);
            Ohttp.Reply reply = Ohttp.decapsulate(request.context(), response);
            assertEquals(200, reply.status());
            assertArrayEquals("ok".getBytes(StandardCharsets.US_ASCII), reply.body());
        } finally {
            if (!process.waitFor(3, TimeUnit.MINUTES)) {
                process.destroyForcibly();
            }
        }
        assertEquals(0, process.exitValue());
    }

    @Test
    void postRoundTripThroughTheLocalRelayAndDirectory() throws Exception {
        Process process = new ProcessBuilder("cargo", "run", "--quiet", "--locked", "--manifest-path",
                DIRECTORY.resolve("Cargo.toml").toString())
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try {
            InputStream stdout = process.getInputStream();
            String relay = readLine(stdout);
            String directory = readLine(stdout);
            String keysHex = readLine(stdout);
            String ready = readLine(stdout);
            assertEquals("READY", ready);
            relay = value(relay, "RELAY");
            directory = value(directory, "DIRECTORY");
            OhttpKeys keys = OhttpKeys.parse(hex(value(keysHex, "KEYS")));
            byte[] body = "original".getBytes(StandardCharsets.US_ASCII);
            String mailbox = directory + "/TXJCGKTKXLUUZ";
            Ohttp.Request request = Ohttp.encapsulate(keys, "POST", mailbox, body, new Random(5));
            HttpRequest http = HttpRequest.newBuilder(URI.create(relay + "/" + directory + "/"))
                    .timeout(Duration.ofSeconds(20))
                    .header("Content-Type", "message/ohttp-req")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(request.encapsulated()))
                    .build();
            HttpResponse<byte[]> response = HttpClient.newHttpClient()
                    .send(http, HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, response.statusCode());
            Ohttp.Reply reply = Ohttp.decapsulate(request.context(), response.body());
            assertEquals(200, reply.status());
            assertEquals(0, reply.body().length);
        } finally {
            process.destroyForcibly();
        }
    }

    private static String value(String line, String name) {
        String prefix = name + "=";
        if (!line.startsWith(prefix)) {
            throw new IllegalStateException(line);
        }
        return line.substring(prefix.length());
    }

    private static String readLine(InputStream in) throws Exception {
        StringBuilder line = new StringBuilder();
        while (true) {
            int next = in.read();
            if (next < 0) {
                throw new IllegalStateException("oracle closed its output");
            }
            if (next == '\n') {
                break;
            }
            if (next != '\r') {
                line.append((char) next);
            }
        }
        return line.toString();
    }

    private static int readInt(InputStream in) throws Exception {
        byte[] bytes = in.readNBytes(4);
        return ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16) | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
