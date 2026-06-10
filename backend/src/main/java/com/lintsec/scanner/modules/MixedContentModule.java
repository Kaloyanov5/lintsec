package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.FindingLocation;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScannerModule;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Passive module: flags HTTPS pages that load active sub-resources (scripts, stylesheets,
 * iframes) over plain HTTP — a network attacker can tamper with those to inject code into the
 * secure page. Passive sub-resources (images, media) are intentionally out of scope.
 */
@Component
public final class MixedContentModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(MixedContentModule.class);

    private record ActiveSelector(String css, String attr) {}

    private static final List<ActiveSelector> ACTIVE = List.of(
            new ActiveSelector("script[src]", "src"),
            new ActiveSelector("link[rel=stylesheet][href]", "href"),
            new ActiveSelector("iframe[src]", "src")
    );

    @Override
    public String name() {
        return "mixed-content";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        for (String url : crawlResult.visitedUrls()) {
            if (!url.toLowerCase(Locale.ROOT).startsWith("https://")) continue;
            Connection.Response resp;
            try {
                resp = context.openConnection(url)
                        .method(Connection.Method.GET)
                        .ignoreHttpErrors(true)
                        .followRedirects(false)
                        .ignoreContentType(true)
                        .execute();
            } catch (Exception e) {
                log.warn("mixed-content fetch failed for {}: {}", url, e.getMessage());
                continue;
            }
            String contentType = resp.contentType();
            if (contentType != null && !contentType.contains("text/html")) continue;

            List<String> insecure = activeHttpSubresources(url, resp.body());
            if (!insecure.isEmpty()) findings.add(finding(url, insecure));
        }
        return findings;
    }

    /**
     * Package-private for unit testing. Returns absolute http:// URLs of active sub-resources on
     * an HTTPS page. Empty if the page is not HTTPS or there are none.
     */
    static List<String> activeHttpSubresources(String pageUrl, String html) {
        List<String> insecure = new ArrayList<>();
        if (pageUrl == null || html == null) return insecure;
        if (!pageUrl.toLowerCase(Locale.ROOT).startsWith("https://")) return insecure;

        Document doc = Jsoup.parse(html, pageUrl);
        for (ActiveSelector sel : ACTIVE) {
            for (Element el : doc.select(sel.css())) {
                String abs = el.absUrl(sel.attr());
                if (abs.toLowerCase(Locale.ROOT).startsWith("http://")) insecure.add(abs);
            }
        }
        return insecure;
    }

    private ScanFinding finding(String url, List<String> resources) {
        return new ScanFinding(
                "Mixed content: active resources loaded over HTTP",
                Severity.MEDIUM,
                name(),
                new FindingLocation(url, null),
                "This HTTPS page loads active sub-resources (scripts, stylesheets, or iframes) over plain HTTP. A network attacker can modify those responses to inject code into the secure page, defeating the protection HTTPS provides. Modern browsers block or warn on active mixed content.",
                "Serve every sub-resource over HTTPS — update absolute http:// URLs to https:// (or protocol-relative //), and add the 'upgrade-insecure-requests' Content-Security-Policy directive to catch any that are missed.",
                null,
                "Insecure resource(s): " + String.join(", ", resources));
    }
}
