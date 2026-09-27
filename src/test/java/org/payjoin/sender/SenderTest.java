package org.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.payjoin.sender.crypto.Secp256k1;
import org.payjoin.sender.uri.Bech32;
import org.payjoin.sender.uri.ShortId;

class SenderTest {
    private static final long EXPIRY = 1_800_000_000L;
    private static final byte[] RECEIVER = secret(1);
    private static final byte[] OHTTP = secret(2);
    private static final String PSBT = Base64.getEncoder().encodeToString(PsbtBytesTest.minimalPsbt());
    private static final String RELAY = "http://relay.example";

    @Test
    void postsThenPollsAndResumesFromTheLog() {
        InMemoryPersister log = new InMemoryPersister();
        Clock clock = Clock.fixed(Instant.ofEpochSecond(EXPIRY - 10), ZoneOffset.UTC);
        Post post = Sender.start(uri(false), PSBT, new Options(1000L, 1, 2L, true), clock, new Random(4), log);
        assertEquals(1, log.load().size());
        EventLog.Event created = EventLog.parse(log.load().get(0));
        assertEquals(false, created.substitution);
        assertEquals(1, created.feeIndex);
        assertEquals(1000L, created.feeSats);
        assertEquals(2L, created.minFee);
        assertEquals(
                "v=2&disableoutputsubstitution=true&additionalfeeoutputindex=1&maxadditionalfeecontribution=1000&minfeerate=2",
                V2Body.query(false, 1, 1000L, 2L));

        Request posted = post.request(RELAY);
        assertEquals("POST", posted.method());
        assertEquals(8192, posted.body().length);
        assertTrue(posted.url().startsWith(RELAY + "/https://payjo.in/"));
        assertInstanceOf(Post.class, Sender.resume(log, clock, new Random(5)));

        Poll poll = post.resume(200, DirectoryResponse.seal(post.context(), 200, new byte[0]));
        assertEquals(2, log.load().size());
        assertEquals("posted", EventLog.parse(log.load().get(1)).type);
        assertInstanceOf(Poll.class, Sender.resume(log, clock, new Random(6)));

        String replyId = ShortId.fromCompressedKey(
                Secp256k1.compressedPublicKey(Hex.decode(created.reply, 32))).toString();
        assertTrue(poll.pollTarget().endsWith("/" + replyId));
        Request get = poll.request(RELAY);
        assertEquals("POST", get.method());
        assertSame(poll, poll.resume(200, DirectoryResponse.seal(poll.context(), 202, new byte[0])));
        get = poll.request(RELAY);
        assertSame(poll, poll.resume(200, DirectoryResponse.seal(poll.context(), 202, new byte[0])));
        assertEquals(2, log.load().size());

        byte[] message = MessagesTest.sealB(PsbtBytesTest.minimalPsbt(), RECEIVER, Hex.decode(created.reply, 32), new Random(7));
        get = poll.request(RELAY);
        Proposal proposal = assertInstanceOf(
                Proposal.class, poll.resume(200, DirectoryResponse.seal(poll.context(), 200, message)));
        assertEquals(PSBT, proposal.psbt());
        Proposal restored = assertInstanceOf(Proposal.class, Sender.resume(log, clock, new Random(8)));
        assertEquals(PSBT, restored.psbt());
    }

    @Test
    void aFailedResponseDoesNotRecordPostedAndAnExpiredPollStops() {
        InMemoryPersister log = new InMemoryPersister();
        MovingClock clock = new MovingClock(EXPIRY - 10);
        Post post = Sender.start(uri(true), PSBT, Options.none(), clock, new Random(9), log);
        post.request(RELAY);
        assertThrows(TransportException.class, () -> post.resume(500, new byte[0]));
        assertEquals(1, log.load().size());
        assertThrows(TransportException.class, () -> post.resume(200, new byte[] {1, 2, 3}));
        post.request(RELAY);
        assertThrows(CounterpartyException.class, () -> post.resume(200, DirectoryResponse.seal(post.context(), 404, new byte[0])));
        assertEquals(1, log.load().size());

        post.request(RELAY);
        Poll poll = post.resume(200, DirectoryResponse.seal(post.context(), 200, new byte[0]));
        poll.request(RELAY);
        clock.seconds = EXPIRY;
        assertThrows(SessionException.class, () -> poll.resume(200, DirectoryResponse.seal(poll.context(), 202, new byte[0])));
        assertThrows(SessionException.class, () -> Sender.resume(log, clock, new Random(10)));

        Post expired = Sender.start(uri(true), PSBT, Options.none(), new MovingClock(EXPIRY), new Random(16), new InMemoryPersister());
        assertThrows(SessionException.class, () -> expired.request(RELAY));
    }

    @Test
    void rejectsABadOriginalAndAReceiverError() {
        InMemoryPersister log = new InMemoryPersister();
        Clock clock = Clock.fixed(Instant.ofEpochSecond(EXPIRY - 10), ZoneOffset.UTC);
        assertThrows(IllegalArgumentException.class, () -> new Options(1L, null, null, false));
        assertThrows(
                IllegalArgumentException.class,
                () -> Sender.start(uri(true), "%%%", Options.none(), clock, new Random(11), log));
        assertEquals(0, log.load().size());

        Post post = Sender.start(uri(true), PSBT, Options.none(), clock, new Random(12), log);
        post.request(RELAY);
        Poll poll = post.resume(200, DirectoryResponse.seal(post.context(), 200, new byte[0]));
        EventLog.Event created = EventLog.parse(log.load().get(0));
        byte[] error = MessagesTest.sealB(
                "{\"error\":\"no\"}".getBytes(StandardCharsets.US_ASCII),
                RECEIVER,
                Hex.decode(created.reply, 32),
                new Random(13));
        poll.request(RELAY);
        assertThrows(CounterpartyException.class, () -> poll.resume(200, DirectoryResponse.seal(poll.context(), 200, error)));
        assertThrows(SessionException.class, () -> Sender.resume(log, clock, new Random(14)));
        assertThrows(SessionException.class, () -> Sender.resume(new InMemoryPersister(), clock, new Random(15)));
    }

    private static String uri(boolean disableSubstitution) {
        byte[] expiry = new byte[] {
            (byte) EXPIRY, (byte) (EXPIRY >>> 8), (byte) (EXPIRY >>> 16), (byte) (EXPIRY >>> 24)
        };
        byte[] ohttp = new byte[34];
        ohttp[0] = 1;
        System.arraycopy(Secp256k1.compressedPublicKey(OHTTP), 0, ohttp, 1, 33);
        String fragment = Bech32.encode("EX", expiry)
                + "-"
                + Bech32.encode("OH", ohttp)
                + "-"
                + Bech32.encode("RK", Secp256k1.compressedPublicKey(RECEIVER));
        String mailbox = "https://payjo.in/TXJCGKTKXLUUZ#" + fragment;
        String pjos = disableSubstitution ? "pjos=0&" : "";
        return "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p?" + pjos + "pj=" + mailbox.replace("#", "%23");
    }

    private static byte[] secret(int tag) {
        byte[] secret = new byte[32];
        secret[31] = (byte) tag;
        return secret;
    }

    private static final class MovingClock extends Clock {
        private long seconds;

        private MovingClock(long seconds) {
            this.seconds = seconds;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochSecond(seconds);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
