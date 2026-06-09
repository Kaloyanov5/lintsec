package com.lintsec.crawler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CrawlerCancellationTest {

    private static CrawlConfig configIgnoringRobots() {
        // ignoreRobots=true -> RobotsTxt.allowAll(), so no network before the loop.
        return new CrawlConfig(2, 50, 10_000, 0, "test-agent", true, AuthSession.anonymous());
    }

    @Test
    void preCancelledTokenVisitsNothing() {
        Crawler crawler = new Crawler(configIgnoringRobots());

        CrawlResult result = crawler.crawl("https://example.com", () -> true);

        assertTrue(result.visitedUrls().isEmpty(), "cancelled crawl must not visit any url");
        assertTrue(result.forms().isEmpty());
    }
}
