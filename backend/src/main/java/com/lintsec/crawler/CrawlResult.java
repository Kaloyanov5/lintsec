package com.lintsec.crawler;

import java.util.List;
import java.util.Set;

public record CrawlResult(
        Set<String> visitedUrls,
        List<DiscoveredForm> forms,
        Set<String> failedUrls
) {
}
