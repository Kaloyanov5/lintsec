package com.lintsec.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Optional;

public class PageFetcher {

    private static final Logger log = LoggerFactory.getLogger(PageFetcher.class);
    private final CrawlConfig config;

    public PageFetcher(CrawlConfig config) {
        this.config = config;
    }

    public Optional<Document> fetch(String url) {
        if (!TargetGuard.isAllowed(url)) {
            log.debug("fetch blocked by SSRF guard: {}", url);
            return Optional.empty();
        }
        org.jsoup.Connection connection = Jsoup.connect(url)
                .userAgent(config.userAgent())
                .timeout(config.timeoutMs())
                .maxBodySize(HttpLimits.MAX_RESPONSE_BYTES)
                .ignoreContentType(true);
        config.authSession().applyTo(connection);

        // Guarded execute follows redirects manually, re-validating each hop so a public page
        // can't 302 the crawler onto an internal address.
        Optional<org.jsoup.Connection.Response> response = GuardedHttp.execute(connection);
        if (response.isEmpty()) return Optional.empty();
        try {
            return Optional.of(response.get().parse());
        } catch (IOException e) {
            log.debug("parse failed for {}: {}", url, e.getMessage());
            return Optional.empty();
        }
    }
}
