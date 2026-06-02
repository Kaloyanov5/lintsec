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
        try {
            org.jsoup.Connection connection = Jsoup.connect(url)
                    .userAgent(config.userAgent())
                    .timeout(config.timeoutMs())
                    .ignoreContentType(true);
            config.authSession().applyTo(connection);
            return Optional.of(connection.get());
        } catch (IOException e) {
            log.debug("fetch failed for {}: {}", url, e.getMessage());
            return Optional.empty();
        }
    }
}
