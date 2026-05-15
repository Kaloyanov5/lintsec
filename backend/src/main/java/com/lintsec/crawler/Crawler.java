package com.lintsec.crawler;

import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class Crawler {

    private static final Logger log = LoggerFactory.getLogger(Crawler.class);
    private final CrawlConfig config;
    private final PageFetcher fetcher;

    public Crawler(CrawlConfig config) {
        this.config = config;
        this.fetcher = new PageFetcher(config);
    }

    public CrawlResult crawl(String startUrl) {
        UrlScope scope = new UrlScope(startUrl);
        ArrayDeque<QueueEntry> queue = new ArrayDeque<>();
        queue.add(new QueueEntry(startUrl, 0));

        Set<String> seen = new HashSet<>();
        Set<String> visitedUrls = new HashSet<>();
        List<DiscoveredForm> forms = new ArrayList<>();
        Set<String> failedUrls = new HashSet<>();

        while (!queue.isEmpty() && visitedUrls.size() < config.maxPages()) {
            QueueEntry entry = queue.poll();
            String url = entry.url();
            int depth = entry.depth();

            if (seen.contains(url)) continue;
            seen.add(url);

            Optional<Document> optionalDocument = fetcher.fetch(url);
            if (optionalDocument.isEmpty()) {
                failedUrls.add(url);
                continue;
            }
            Document document = optionalDocument.get();
            visitedUrls.add(url);
            forms.addAll(FormExtractor.extractForms(document));
            if (depth < config.maxDepth()) {
                for (String link : LinkExtractor.extractLinks(document)) {
                    if (scope.isInScope(link) && !seen.contains(link)) {
                        queue.add(new QueueEntry(link, depth + 1));
                    }
                }
            }
        }

        log.info("crawl complete: visited={} failed={} forms={}", visitedUrls.size(), failedUrls.size(), forms.size());
        return new CrawlResult(visitedUrls, forms, failedUrls);
    }

    private record QueueEntry(
            String url,
            int depth
    ) { }
}
