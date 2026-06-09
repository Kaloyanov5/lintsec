package com.lintsec.crawler;

import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.*;

public class Crawler {

    private static final Logger log = LoggerFactory.getLogger(Crawler.class);
    private final CrawlConfig config;
    private final PageFetcher fetcher;

    // GET links that mutate session or security state — following them sabotages the scan:
    // logout/signout kill the authenticated session; phpids toggles an intrusion-detection
    // system that then blocks the active modules' probe payloads (e.g. the SQLi single-quote).
    private static final java.util.List<String> STATE_CHANGING_LINK_MARKERS =
            java.util.List.of("logout", "signout", "sign-out", "logoff", "phpids");

    public Crawler(CrawlConfig config) {
        this.config = config;
        this.fetcher = new PageFetcher(config);
    }

    public CrawlResult crawl(String startUrl, CancellationToken cancellationToken) {
        UrlScope scope = new UrlScope(startUrl);
        RobotsTxt robots = config.ignoreRobots()
                ? RobotsTxt.allowAll()
                : RobotsTxt.fetch(startUrl, config.userAgent(), config.timeoutMs());
        int effectiveDelayMs = Math.max(config.delayMs(), robots.crawlDelayMs().orElse(0));
        ArrayDeque<QueueEntry> queue = new ArrayDeque<>();
        queue.add(new QueueEntry(startUrl, 0));

        Set<String> seen = new HashSet<>();
        Set<String> visitedUrls = new HashSet<>();
        List<DiscoveredForm> forms = new ArrayList<>();
        Set<String> formSignatures = new HashSet<>();
        Set<String> failedUrls = new HashSet<>();

        while (!queue.isEmpty() && visitedUrls.size() < config.maxPages()) {
            if (cancellationToken.isCancellationRequested()) {
                log.info("crawl cancelled after {} pages", visitedUrls.size());
                break;
            }
            QueueEntry entry = queue.poll();
            String url = entry.url();
            int depth = entry.depth();

            if (seen.contains(url)) continue;
            seen.add(url);
            String path = URI.create(url).getPath();
            if (path == null || path.isEmpty()) path = "/";
            if (!robots.isAllowed(path)) {
                continue;
            }

            Optional<Document> optionalDocument = fetcher.fetch(url);
            if (optionalDocument.isEmpty()) {
                failedUrls.add(url);
                continue;
            }
            Document document = optionalDocument.get();
            visitedUrls.add(url);
            for (DiscoveredForm form : FormExtractor.extractForms(document)) {
                // The same form (e.g. a header search box) appears on many pages;
                // probe each distinct shape once.
                if (formSignatures.add(form.signature())) {
                    forms.add(form);
                }
            }
            if (depth < config.maxDepth()) {
                for (String link : LinkExtractor.extractLinks(document)) {
                    if (scope.isInScope(link) && !seen.contains(link) && !isStateChangingLink(link)) {
                        queue.add(new QueueEntry(link, depth + 1));
                    }
                }
            }

            if (effectiveDelayMs > 0) {
                try {
                    Thread.sleep(effectiveDelayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        log.info("crawl complete: visited={} failed={} forms={}", visitedUrls.size(), failedUrls.size(), forms.size());
        return new CrawlResult(visitedUrls, forms, failedUrls);
    }

    // Substring match is intentionally broad: skipping an over-matched link only forgoes a probe,
    // never breaks the scan. Tighten to path/query-key matching if real targets get under-crawled.
    static boolean isStateChangingLink(String url) {
        String lower = url.toLowerCase(java.util.Locale.ROOT);
        for (String marker : STATE_CHANGING_LINK_MARKERS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    private record QueueEntry(
            String url,
            int depth
    ) { }
}
