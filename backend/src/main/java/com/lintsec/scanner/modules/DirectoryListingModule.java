package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.FindingLocation;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScannerModule;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects auto-generated directory index pages (Apache autoindex, nginx, Tomcat/Jetty, IIS),
 * which leak the file/directory structure of the server and often expose files not meant to be
 * linked (backups, configs, source).
 */
@Component
public final class DirectoryListingModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(DirectoryListingModule.class);

    private record Signature(String server, String marker) {}

    // Distinctive markers from each server's directory-listing template. Matched case-insensitively
    // against the response body; kept specific enough to avoid matching ordinary pages.
    private static final List<Signature> SIGNATURES = List.of(
            new Signature("Apache/nginx", "<title>index of /"),
            new Signature("Apache/nginx", "<h1>index of /"),
            new Signature("Tomcat/Jetty", "directory listing for"),
            new Signature("IIS", "<pre><a href=\"/")
    );

    @Override
    public String name() {
        return "directory-listing";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        for (String url : crawlResult.visitedUrls()) {
            Connection.Response resp;
            try {
                resp = Jsoup.connect(url)
                        .userAgent(context.userAgent())
                        .timeout(context.timeoutMs())
                        .method(Connection.Method.GET)
                        .ignoreHttpErrors(true)
                        .followRedirects(true)
                        .ignoreContentType(true)
                        .execute();
            } catch (Exception e) {
                log.warn("failed to fetch URL: {}", url, e);
                continue;
            }

            String contentType = resp.contentType();
            if (contentType != null && !contentType.contains("text/html")) continue;

            String body = resp.body();
            String haystack = body.length() > 4096 ? body.substring(0, 4096).toLowerCase() : body.toLowerCase();

            for (Signature sig : SIGNATURES) {
                if (haystack.contains(sig.marker)) {
                    findings.add(new ScanFinding(
                            "Directory listing enabled",
                            Severity.MEDIUM,
                            name(),
                            new FindingLocation(url, null),
                            "The server returns an auto-generated directory index instead of a page, exposing the names of every file in this directory. This reveals the application's structure and frequently discloses files that were never meant to be reachable — backups, archives, configuration, version-control metadata, or source code.",
                            "Disable automatic directory indexing. Apache: 'Options -Indexes'. nginx: 'autoindex off'. Tomcat: set the DefaultServlet 'listings' init-param to false. IIS: disable Directory Browsing. Place an index file in directories that should be browsable.",
                            null,
                            "Response body matched a " + sig.server + " directory-listing signature."
                    ));
                    break; // one finding per URL
                }
            }
        }

        return findings;
    }
}
