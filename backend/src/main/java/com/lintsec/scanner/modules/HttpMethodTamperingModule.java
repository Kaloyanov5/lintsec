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

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Probes for dangerous HTTP methods. It only ever <em>sends</em> the side-effect-free verbs OPTIONS
 * and TRACE; destructive methods (PUT/DELETE/WebDAV) are detected from the advertised {@code Allow}
 * header, never invoked. TRACE is tested once per host (it's a server-wide setting); OPTIONS findings
 * are deduped per host + advertised-method-set so a 50-page crawl yields one finding, not fifty.
 */
@Component
public final class HttpMethodTamperingModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(HttpMethodTamperingModule.class);

    // Methods that can create/modify/delete server-side content -> HIGH if advertised.
    private static final Set<String> WEBDAV_WRITE = Set.of(
            "PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"
    );
    // Methods that widen attack surface but aren't directly destructive -> MEDIUM if advertised.
    private static final Set<String> OTHER_RISKY = Set.of("TRACE", "CONNECT", "PATCH");

    @Override
    public String name() {
        return "http-method-tampering";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        Set<String> reportedOptions = new HashSet<>();  // host + risky-method-set
        Set<String> tracedHosts = new HashSet<>();

        for (String url : crawlResult.visitedUrls()) {
            probe(url, Connection.Method.OPTIONS, context).ifPresent(resp -> {
                String allow = resp.header("Allow");
                if (allow == null || allow.isBlank()) return;

                List<String> risky = parseMethods(allow).stream()
                        .filter(m -> WEBDAV_WRITE.contains(m) || OTHER_RISKY.contains(m))
                        .sorted()
                        .toList();
                if (risky.isEmpty()) return;
                if (!reportedOptions.add(hostKey(url) + risky)) return;

                boolean writeCapable = risky.stream().anyMatch(WEBDAV_WRITE::contains);
                findings.add(new ScanFinding(
                        "Risky HTTP methods advertised: " + String.join(", ", risky),
                        writeCapable ? Severity.HIGH : Severity.MEDIUM,
                        name(),
                        new FindingLocation(url, null),
                        writeCapable
                                ? "The server's Allow header advertises HTTP methods that can modify server-side content (PUT, DELETE, or WebDAV verbs). If any are not strictly access-controlled, an attacker may upload, overwrite, or delete files directly — potentially achieving remote code execution by writing an executable script into a served directory."
                                : "The server's Allow header advertises HTTP methods (TRACE, CONNECT, or PATCH) that are rarely required and enlarge the attack surface. TRACE in particular can enable Cross-Site Tracing (XST) to read otherwise-protected request headers.",
                        "Disable HTTP methods the application does not use, restricting each endpoint to the verbs it needs (typically GET/POST/HEAD). For WebDAV, disable the module or enforce authentication and authorization on all write methods.",
                        null,
                        "OPTIONS response Allow header advertised: " + allow
                ));
            });

            // TRACE is a server-wide setting; test it once per host.
            if (tracedHosts.add(hostKey(url))) {
                probe(url, Connection.Method.TRACE, context).ifPresent(resp -> {
                    if (resp.statusCode() == 200) {
                        findings.add(new ScanFinding(
                                "HTTP TRACE method enabled",
                                Severity.MEDIUM,
                                name(),
                                new FindingLocation(url, null),
                                "The server responds to HTTP TRACE with 200, echoing the request back. Combined with another flaw, this enables Cross-Site Tracing (XST): an attacker can read request headers — including HttpOnly cookies or auth headers — that JavaScript could not otherwise reach.",
                                "Disable the TRACE method at the web server or proxy. Apache: 'TraceEnable off'. Most application servers expose a configuration switch for this; nginx does not implement TRACE by default.",
                                null,
                                "TRACE request returned HTTP 200."
                        ));
                    }
                });
            }
        }

        return findings;
    }

    private Optional<Connection.Response> probe(String url, Connection.Method method, ScanContext context) {
        try {
            return Optional.of(Jsoup.connect(url)
                    .userAgent(context.userAgent())
                    .timeout(context.timeoutMs())
                    .method(method)
                    .ignoreHttpErrors(true)
                    .followRedirects(false)
                    .ignoreContentType(true)
                    .execute());
        } catch (Exception e) {
            log.warn("{} probe failed for {}: {}", method, url, e.getMessage());
            return Optional.empty();
        }
    }

    private static Set<String> parseMethods(String allowHeader) {
        Set<String> methods = new HashSet<>();
        for (String m : allowHeader.split(",")) {
            String trimmed = m.trim().toUpperCase(Locale.ROOT);
            if (!trimmed.isEmpty()) methods.add(trimmed);
        }
        return methods;
    }

    private static String hostKey(String url) {
        try {
            URI u = URI.create(url);
            return u.getScheme() + "://" + u.getAuthority();
        } catch (Exception e) {
            return url;
        }
    }
}
