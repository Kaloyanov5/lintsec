package com.lintsec.crawler;

public record CrawlConfig(
        int maxDepth,
        int maxPages,
        int timeoutMs,
        String userAgent
) {
    public CrawlConfig {
        if (maxDepth < 0 || maxDepth > 3) {
            throw new IllegalArgumentException("Invalid crawler depth");
        }
        if (maxPages <= 0 || maxPages > 50) {
            throw new IllegalArgumentException("Invalid crawled page count");
        }
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("Invalid crawler timeout");
        }
        if (userAgent == null || userAgent.isBlank()) {
            throw new IllegalArgumentException("Invalid crawl user agent");
        }
    }

    public static CrawlConfig defaults() {
        return new CrawlConfig(
                2,
                50,
                10000,
                "LintSec-Scanner/1.0"
        );
    }
}
