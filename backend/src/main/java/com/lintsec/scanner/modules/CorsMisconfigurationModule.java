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
import java.util.Optional;

@Component
public final class CorsMisconfigurationModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(CorsMisconfigurationModule.class);

    private static final String EVIL_ORIGIN = "https://evil.example.com";
    private static final String NULL_ORIGIN = "null";

    @Override
    public String name() {
        return "cors-misconfig";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        for (String url : crawlResult.visitedUrls()) {
            probeWithOrigin(url, EVIL_ORIGIN, context).ifPresent(resp -> {
                String allowOrigin = resp.header("Access-Control-Allow-Origin");
                String allowCredentials = resp.header("Access-Control-Allow-Credentials");
                boolean credentialsAllowed = "true".equalsIgnoreCase(allowCredentials);

                // Rule 1: origin reflected verbatim
                if (EVIL_ORIGIN.equalsIgnoreCase(allowOrigin)) {
                    String credentialsSuffix = credentialsAllowed
                            ? " AND Access-Control-Allow-Credentials=true — attacker can read authenticated responses from this endpoint cross-origin."
                            : ".";
                    findings.add(new ScanFinding(
                            "CORS reflects arbitrary Origin",
                            Severity.HIGH,
                            name(),
                            new FindingLocation(url, "Origin"),
                            "The server echoes any Origin sent by the client into Access-Control-Allow-Origin without validation. An attacker hosting a page on any domain can issue cross-origin requests against this endpoint, and the browser will treat the response as same-origin. If credentials are also allowed, the attacker can read authenticated data.",
                            "Validate the Origin against an explicit allow-list before echoing it back. Do not dynamically reflect arbitrary origins. If only first-party origins should reach this endpoint, set Access-Control-Allow-Origin to that exact origin, not the request Origin.",
                            null,
                            "Sent Origin: " + EVIL_ORIGIN + "; server replied Access-Control-Allow-Origin: " + allowOrigin + credentialsSuffix
                    ));
                }

                // Rule 2: wildcard + credentials (browsers reject, but server is misconfigured)
                if ("*".equals(allowOrigin) && credentialsAllowed) {
                    findings.add(new ScanFinding(
                            "CORS wildcard with credentials",
                            Severity.HIGH,
                            name(),
                            new FindingLocation(url, "Origin"),
                            "The server sets Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers reject this combination as a safety measure, but the configuration itself indicates the developer intended to allow any origin to read authenticated responses — a serious model error that may be exploitable through alternative paths.",
                            "Decide whether the endpoint should accept credentials. If yes, replace the wildcard with an explicit allow-list of trusted origins. If no, remove Access-Control-Allow-Credentials.",
                            null,
                            "Server replied Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
                    ));
                }

                // Rule 4: wildcard on API-shaped endpoint
                if ("*".equals(allowOrigin) && !credentialsAllowed && looksLikeApi(url)) {
                    findings.add(new ScanFinding(
                            "CORS wildcard on API endpoint",
                            Severity.LOW,
                            name(),
                            new FindingLocation(url, "Origin"),
                            "The endpoint returns Access-Control-Allow-Origin: *, allowing any origin to read responses. Without credentials this does not expose authenticated data, but it does enable arbitrary third parties to consume the API from browsers, including data that might be considered internal.",
                            "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins. Use '*' only for genuinely public, non-sensitive APIs (e.g. CDNs, public datasets).",
                            null,
                            "API-shaped URL (" + url + ") returned Access-Control-Allow-Origin: *."
                    ));
                }
            });

            probeWithOrigin(url, NULL_ORIGIN, context).ifPresent(resp -> {
                String allowOrigin = resp.header("Access-Control-Allow-Origin");

                // Rule 3: null origin allowed
                if ("null".equalsIgnoreCase(allowOrigin)) {
                    findings.add(new ScanFinding(
                            "CORS allows null Origin",
                            Severity.MEDIUM,
                            name(),
                            new FindingLocation(url, "Origin"),
                            "The server accepts the literal 'null' Origin, which is produced by sandboxed iframes, data: URIs, and certain redirect chains. An attacker can craft a sandboxed context that issues cross-origin requests appearing to come from a null origin, bypassing intended CORS restrictions.",
                            "Never allow Origin: null. Treat it as untrusted and either omit Access-Control-Allow-Origin or return an explicit allow-listed origin.",
                            null,
                            "Sent Origin: null; server replied Access-Control-Allow-Origin: " + allowOrigin + "."
                    ));
                }
            });
        }

        return findings;
    }

    private Optional<Connection.Response> probeWithOrigin(String url, String origin, ScanContext context) {
        try {
            return Optional.of(Jsoup.connect(url)
                    .userAgent(context.userAgent())
                    .timeout(context.timeoutMs())
                    .header("Origin", origin)
                    .method(Connection.Method.GET)
                    .ignoreHttpErrors(true)
                    .followRedirects(false)
                    .ignoreContentType(true)
                    .execute());
        } catch (Exception e) {
            log.warn("CORS probe failed for {} with origin {}: {}", url, origin, e.getMessage());
            return Optional.empty();
        }
    }

    private static boolean looksLikeApi(String url) {
        String lower = url.toLowerCase();
        return lower.contains("/api/") || lower.contains("/rest/") || lower.endsWith(".json");
    }
}
