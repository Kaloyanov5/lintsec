package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.*;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public final class OpenRedirectModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(OpenRedirectModule.class);

    private static final Set<String> REDIRECT_PARAM_NAMES = Set.of(
            "redirect", "redirect_url", "redirect_uri", "redirecturl", "redirecturi",
            "next", "next_url", "nexturl",
            "url", "dest", "destination",
            "return", "return_url", "returnurl", "returnto",
            "continue", "callback", "r", "u"
    );

    private static final List<Integer> TARGET_STATUS_CODES = List.of(301, 302, 303, 307, 308);

    @Override
    public String name() {
        return "open-redirect";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        for (String url : crawlResult.visitedUrls()) {
            URI uri = URI.create(url);
            List<Map.Entry<String, String>> parameterEntries = UrlParams.parseQueryParameters(uri);

            for (Map.Entry<String, String> entry : parameterEntries) {
                String paramName = entry.getKey();

                if (REDIRECT_PARAM_NAMES.contains(paramName.toLowerCase())) {
                    String payload = PayloadCatalog.payloadFor(PayloadId.OPEN_REDIRECT_ABSOLUTE, "");
                    String mutatedUrl = UrlParams.replaceQueryParameters(url, paramName, payload);

                    Connection.Response resp;
                    try {
                        resp = Jsoup.connect(mutatedUrl)
                                .userAgent(context.userAgent())
                                .timeout(context.timeoutMs())
                                .method(Connection.Method.GET)
                                .ignoreHttpErrors(true)
                                .followRedirects(false)
                                .execute();
                        log.debug("fetched URL: {} with status {}", url, resp.statusCode());
                    } catch (Exception e) {
                        log.warn("failed to fetch URL: {}", url, e);
                        continue;
                    }

                    if (TARGET_STATUS_CODES.contains(resp.statusCode()) && locationPointsToPayload(resp.header("Location"), payload)) {
                        findings.add(new ScanFinding(
                                "Open redirect via parameter: " + paramName,
                                Severity.HIGH,
                                name(),
                                new FindingLocation(url, paramName),
                                "A URL query parameter accepts arbitrary external destinations. An attacker can craft a link on this host that redirects victims to an attacker-controlled site, enabling phishing and credential harvesting.",
                                "Validate the redirect target against an allow-list of paths or hosts. If only same-origin redirects are needed, require relative URLs (reject any value containing '://').",
                                PayloadId.OPEN_REDIRECT_ABSOLUTE,
                                "Server responded with " + resp.statusCode() + "; Location header pointed to the injected external URL."
                        ));
                    }
                }
            }
        }

        return findings;
    }

    private static boolean locationPointsToPayload(String location, String payload) {
        if (location == null || location.isBlank()) return false;
        if (location.startsWith(payload)) return true;
        // URL-decoded form (some frameworks double-encode then decode)
        try {
            String decoded = URLDecoder.decode(location, StandardCharsets.UTF_8);
            return decoded.startsWith(payload);
        } catch (Exception e) {
            return false;
        }
    }
}
