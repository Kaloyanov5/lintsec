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
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Passive module: flags cross-origin scripts and stylesheets loaded without a Subresource
 * Integrity (integrity) attribute. Without SRI, a compromised third-party/CDN host can serve
 * tampered code that the browser will execute. Same-origin resources are ignored.
 */
@Component
public final class MissingSriModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(MissingSriModule.class);

    @Override
    public String name() {
        return "missing-sri";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        for (String url : crawlResult.visitedUrls()) {
            Connection.Response resp;
            try {
                resp = context.openConnection(url)
                        .method(Connection.Method.GET)
                        .ignoreHttpErrors(true)
                        .followRedirects(true)
                        .ignoreContentType(true)
                        .execute();
            } catch (Exception e) {
                log.warn("missing-sri fetch failed for {}: {}", url, e.getMessage());
                continue;
            }
            String contentType = resp.contentType();
            if (contentType != null && !contentType.contains("text/html")) continue;

            List<String> resources = crossOriginResourcesMissingIntegrity(url, resp.body());
            if (!resources.isEmpty()) findings.add(finding(url, resources));
        }
        return findings;
    }

    /**
     * Package-private for unit testing. Returns absolute URLs of cross-origin script/stylesheet
     * resources that lack an integrity attribute.
     */
    static List<String> crossOriginResourcesMissingIntegrity(String pageUrl, String html) {
        List<String> result = new ArrayList<>();
        if (pageUrl == null || html == null) return result;
        String pageHost;
        try {
            pageHost = URI.create(pageUrl).getHost();
        } catch (Exception e) {
            return result;
        }
        if (pageHost == null) return result;

        Document doc = Jsoup.parse(html, pageUrl);
        collect(doc.select("script[src]"), "src", pageHost, result);
        collect(doc.select("link[rel=stylesheet][href]"), "href", pageHost, result);
        return result;
    }

    private static void collect(Elements elements, String attr, String pageHost, List<String> out) {
        for (Element el : elements) {
            String abs = el.absUrl(attr);
            if (abs.isBlank()) continue;
            String host;
            try {
                host = URI.create(abs).getHost();
            } catch (Exception e) {
                continue;
            }
            if (host == null || host.equalsIgnoreCase(pageHost)) continue; // same-origin / relative
            if (el.attr("integrity").isBlank()) out.add(abs);
        }
    }

    private ScanFinding finding(String url, List<String> resources) {
        return new ScanFinding(
                "Third-party resources loaded without Subresource Integrity",
                Severity.LOW,
                name(),
                new FindingLocation(url, null),
                "This page loads scripts or stylesheets from another origin without an 'integrity' (Subresource Integrity) attribute. If the third-party/CDN host is compromised or the response is tampered with in transit, the browser will execute the altered code with no protection.",
                "Add an 'integrity' SRI hash and 'crossorigin' attribute to third-party <script> and <link rel=stylesheet> tags, or self-host the resources so they are covered by your own controls.",
                null,
                "Resource(s) without integrity: " + String.join(", ", resources));
    }
}
