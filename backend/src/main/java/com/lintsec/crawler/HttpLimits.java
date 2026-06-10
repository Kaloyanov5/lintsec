package com.lintsec.crawler;

/** Shared HTTP limits for scanned-target requests. */
public final class HttpLimits {

    private HttpLimits() {}

    /**
     * Max bytes JSoup reads from any scanned response. Modules fetch arbitrary target content with
     * {@code ignoreContentType(true)}, so without a cap a large/streamed response could exhaust
     * memory — multiplied across concurrent scans. JSoup's own default is 2 MB; we set it
     * explicitly so the cap is intentional and consistent everywhere.
     */
    public static final int MAX_RESPONSE_BYTES = 2_000_000;
}
