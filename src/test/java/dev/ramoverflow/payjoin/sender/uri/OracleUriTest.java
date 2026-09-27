package dev.ramoverflow.payjoin.sender.uri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Compares canonical URIs with a local payjoin-ffi build. The test is skipped
 * when that build is not on the machine.
 */
@Tag("oracle")
class OracleUriTest {
    private static final String EXAMPLE = "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p"
            + "?amount=0.00666666&pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ"
            + "%23EX1WKV8CEC-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ"
            + "-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    @Test
    void canonicalFormMatchesTheReference() throws Exception {
        assumeTrue(System.getProperty("payjoin.oracle.native") != null, "payjoin-ffi is not built");
        String reordered = "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p?amount=0.00666666&pjos=0"
                + "&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ"
                + "%23RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV"
                + "-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ"
                + "-EX1WKV8CEC";
        String plus = reordered.replace("-OH1", "+OH1").replace("-EX1", "+EX1");
        Class<?> uriClass = Class.forName("dev.ramoverflow.payjoindevkit.Uri");
        Object companion = uriClass.getField("Companion").get(null);
        Method parse = companion.getClass().getMethod("parse", String.class);
        for (String uri : new String[] {EXAMPLE, reordered, plus}) {
            Object parsed = parse.invoke(companion, uri);
            try {
                Object supported = parsed.getClass().getMethod("checkPjSupported").invoke(parsed);
                try {
                    String canonical = (String) supported.getClass().getMethod("asString").invoke(supported);
                    assertEquals(canonical, PayjoinUri.parse(uri).toString());
                } finally {
                    ((AutoCloseable) supported).close();
                }
            } finally {
                ((AutoCloseable) parsed).close();
            }
        }
    }
}
