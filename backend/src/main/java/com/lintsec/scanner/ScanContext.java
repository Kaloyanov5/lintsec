package com.lintsec.scanner;

import com.lintsec.crawler.AuthSession;
import com.lintsec.crawler.HttpLimits;
import org.jsoup.Connection;
import org.jsoup.Jsoup;

public record ScanContext(
        String userAgent,
        int timeoutMs,
        boolean followRedirects,
        AuthSession authSession
) {
    public ScanContext {
        if (userAgent == null || userAgent.isBlank()) throw new IllegalArgumentException("userAgent required");
        if (timeoutMs <= 0) throw new IllegalArgumentException("timeoutMs must be positive");
        if (authSession == null) authSession = AuthSession.anonymous();
    }

    /**
     * A JSoup connection pre-configured with this context's user agent, timeout, and
     * authenticated session cookies. Callers set method/data/followRedirects/headers and
     * call execute(). This is the single place auth is attached for module requests.
     */
    public Connection openConnection(String url) {
        Connection connection = Jsoup.connect(url)
                .userAgent(userAgent)
                .timeout(timeoutMs)
                .maxBodySize(HttpLimits.MAX_RESPONSE_BYTES);
        authSession.applyTo(connection);
        return connection;
    }
}
