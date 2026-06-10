package com.lintsec.crawler;

import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.Optional;

/**
 * Executes a JSoup request while re-validating every redirect hop against {@link TargetGuard}.
 *
 * <p>{@link TargetGuard#isAllowed} only checks the URL we're about to request — but JSoup's own
 * redirect-following would transparently chase a {@code 302 Location: http://169.254.169.254/}
 * issued by an otherwise-public target, re-opening the SSRF hole. So we disable JSoup's automatic
 * following and walk the chain ourselves, running the guard before each hop. Re-validating per hop
 * also shrinks the DNS-rebinding window, since each hop is resolved-and-checked immediately before
 * it is fetched. Fail-closed: a blocked hop, too many hops, or any error yields empty.
 */
public final class GuardedHttp {

    private static final Logger log = LoggerFactory.getLogger(GuardedHttp.class);
    private static final int MAX_REDIRECTS = 5;

    private GuardedHttp() {}

    /**
     * Executes {@code connection} (method/data/headers already configured), following up to
     * {@value #MAX_REDIRECTS} redirects with a guard check before each request. The connection's
     * auth cookies/headers are reused on every hop.
     */
    public static Optional<Connection.Response> execute(Connection connection) {
        connection.followRedirects(false);
        try {
            String currentUrl = connection.request().url().toExternalForm();
            for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
                if (!TargetGuard.isAllowed(currentUrl)) {
                    log.debug("guarded request blocked at hop {}: {}", hop, currentUrl);
                    return Optional.empty();
                }
                Connection.Response response = connection.url(currentUrl).execute();
                int code = response.statusCode();
                if (code >= 300 && code < 400 && response.hasHeader("Location")) {
                    currentUrl = new URL(response.url(), response.header("Location")).toExternalForm();
                    continue;
                }
                return Optional.of(response);
            }
            log.debug("guarded request exceeded {} redirects", MAX_REDIRECTS);
            return Optional.empty();
        } catch (Exception e) {
            log.debug("guarded request failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
