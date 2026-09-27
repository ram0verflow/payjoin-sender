package dev.ramoverflow.payjoin.sender;

import java.util.Arrays;

/**
 * What the caller sends to the OHTTP relay.
 * The method is always POST. The inner Binary HTTP method is inside {@code body}.
 * Set {@code Content-Type} to {@link #CONTENT_TYPE}.
 */
public final class Request {
    /** Media type of an encapsulated request. */
    public static final String CONTENT_TYPE = "message/ohttp-req";

    private final String url;
    private final String method;
    private final byte[] body;

    Request(String url, String method, byte[] body) {
        this.url = url;
        this.method = method;
        this.body = body.clone();
    }

    /** Absolute URL the caller POSTs to. */
    public String url() {
        return url;
    }

    /** Always {@code POST}. */
    public String method() {
        return method;
    }

    /** A copy of the encapsulated body. */
    public byte[] body() {
        return body.clone();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object other) {
        return other instanceof Request that
                && url.equals(that.url)
                && method.equals(that.method)
                && Arrays.equals(body, that.body);
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return url.hashCode() ^ method.hashCode() ^ Arrays.hashCode(body);
    }
}
