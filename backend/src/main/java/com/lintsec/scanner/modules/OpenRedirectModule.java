package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.*;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

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
            List<Map.Entry<String, String>> parameterEntries = parseQueryParameters(uri);

            for (Map.Entry<String, String> entry : parameterEntries) {
                String paramName = entry.getKey();
                String paramValue = entry.getValue();

                if (REDIRECT_PARAM_NAMES.contains(paramName.toLowerCase())) {
                    String payload = PayloadCatalog.payloadFor(PayloadId.OPEN_REDIRECT_ABSOLUTE, "");
                    String mutatedUrl = replaceQueryParameters(url, paramName, payload);

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

    private static List<Map.Entry<String, String>> parseQueryParameters(URI uri) {
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return List.of();
        }

        List<Map.Entry<String, String>> parameters = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }

            int equalsIndex = pair.indexOf('=');
            String rawName = equalsIndex >= 0 ? pair.substring(0, equalsIndex) : pair;
            String rawValue = equalsIndex >= 0 ? pair.substring(equalsIndex + 1) : "";

            parameters.add(new AbstractMap.SimpleEntry<>(
                    URLDecoder.decode(rawName, StandardCharsets.UTF_8),
                    URLDecoder.decode(rawValue, StandardCharsets.UTF_8)
            ));
        }

        return parameters;
    }

    private static String replaceQueryParameters(String url, String targetParam, String newValue) {
        URI uri = URI.create(url);
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return url;
        }

        StringBuilder newQueryBuilder = new StringBuilder();
        String[] pairs = rawQuery.split("&");
        for (int i = 0; i < pairs.length; i++) {
            String[] parts = pairs[i].split("=", 2);
            String paramName = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);

            if (i > 0) {
                newQueryBuilder.append("&");
            }

            newQueryBuilder.append(parts[0]).append("=");
            if (paramName.equalsIgnoreCase(targetParam)) {
                newQueryBuilder.append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
            } else {
                newQueryBuilder.append(parts.length > 1 ? parts[1] : "");
            }
        }

        try {
            return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), newQueryBuilder.toString(), uri.getFragment()).toString();
        } catch (Exception e) {
            log.warn("Failed to reconstruct URI", e);
            return url;
        }
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
