package com.lintsec.crawler;

public record CrawlConfig(
        int maxDepth,
        int maxPages,
        int timeoutMs,
        int delayMs,
        String userAgent,
        boolean ignoreRobots,
        AuthSession authSession
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
        if (delayMs < 0 || delayMs > 5000) {
            throw new IllegalArgumentException("Invalid crawler delay");
        }
        if (userAgent == null || userAgent.isBlank()) {
            throw new IllegalArgumentException("Invalid crawl user agent");
        }
        if (authSession == null) {
            authSession = AuthSession.anonymous();
        }
    }

    public static CrawlConfig defaults() {
        return new CrawlConfig(
                2,
                50,
                10000,
                500,
                "LintSec-Scanner/1.0",
                false,
                AuthSession.anonymous()
        );
    }
}
