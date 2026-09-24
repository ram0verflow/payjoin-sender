package org.payjoin.sender.uri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PayjoinUriTest {
    private static final String BIP77 = "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p"
            + "?amount=0.00666666&pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ"
            + "%23EX1WKV8CEC-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ"
            + "-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    @Test
    void parsesTheBip77Example() {
        PayjoinUri uri = PayjoinUri.parse(BIP77);
        assertEquals("tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p", uri.address());
        assertEquals(666666L, uri.amountSats());
        assertFalse(uri.outputSubstitution());
        assertEquals("TXJCGKTKXLUUZ", uri.shortId().toString());
        assertEquals(1736218741L, uri.expirationUnix());
        assertEquals(1, uri.ohttpKeyId());
        assertEquals(BIP77, uri.toString());
        assertEquals("TXJCGKTKXLUUZ", ShortId.fromCompressedKey(uri.receiverKey()).toString());
    }

    @Test
    void acceptsLegacyPlusSeparatorsAndEmitsDashesInOrder() {
        String plus = "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p?amount=0.00666666&pjos=0"
                + "&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ"
                + "%23RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV"
                + "+OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ"
                + "+EX1WKV8CEC";
        assertEquals(BIP77, PayjoinUri.parse(plus).toString());
    }

    @Test
    void rejectsALowercaseFragment() {
        String lowercase = BIP77.replace("EX1WKV8CEC", "ex1wkv8cec");
        UriParseException error = assertThrows(UriParseException.class, () -> PayjoinUri.parse(lowercase));
        assertEquals(UriParseException.Reason.LOWERCASE_FRAGMENT, error.reason());
    }

    @Test
    void rejectsMixedDelimiters() {
        String mixed = BIP77.replace("-OH1", "+OH1");
        UriParseException error = assertThrows(UriParseException.class, () -> PayjoinUri.parse(mixed));
        assertEquals(UriParseException.Reason.AMBIGUOUS_DELIMITER, error.reason());
    }

    @Test
    void rejectsAMissingSessionParameter() {
        String missing = BIP77.replace("-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV", "");
        UriParseException error = assertThrows(UriParseException.class, () -> PayjoinUri.parse(missing));
        assertEquals(UriParseException.Reason.NOT_V2, error.reason());
    }
}
