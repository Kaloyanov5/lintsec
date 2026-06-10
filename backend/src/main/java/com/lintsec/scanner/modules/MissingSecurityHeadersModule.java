package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.*;
import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

@Component
public final class MissingSecurityHeadersModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(MissingSecurityHeadersModule.class);

    private record HeaderRule(
            String headerName,
            Severity severity,
            String description,
            String remediation,
            boolean requiresHttps,
            Predicate<String> valueIsValid
    ) {}

    private static final List<HeaderRule> RULES = List.of(
            new HeaderRule(
                    "Content-Security-Policy",
                    Severity.HIGH,
                    "Defense-in-depth against XSS via resource loading restrictions.",
                    "Set Content-Security-Policy to a restrictive policy; start with default-src 'self'.",
                    false,
                    v -> !v.isBlank()
            ), new HeaderRule(
                    "Strict-Transport-Security",
                    Severity.HIGH,
                    "Forces browsers to use HTTPS for future requests, preventing SSL stripping and downgrade attacks.",
                    "Set Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses.",
                    true,
                    v -> !v.isBlank()
            ), new HeaderRule(
                    "X-Frame-Options",
                    Severity.MEDIUM,
                    "Prevents the page from being framed by other origins, defending against clickjacking.",
                    "Set X-Frame-Options: DENY (or use CSP frame-ancestors 'none').",
                    false,
                    v -> !v.isBlank()
            ), new HeaderRule(
                    "X-Content-Type-Options",
                    Severity.LOW,
                    "Stops browsers from MIME-sniffing responses away from the declared Content-Type, blocking some XSS via served files.",
                    "Set X-Content-Type-Options: nosniff on all responses.",
                    false,
                    v -> v.trim().equalsIgnoreCase("nosniff")
            ), new HeaderRule(
                    "Referrer-Policy",
                    Severity.LOW,
                    "Controls how much referrer information is sent on outbound navigation, reducing cross-origin info leakage.",
                    "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
                    false,
                    v -> !v.isBlank()
            )
    );

    @Override
    public String name() {
        return "missing-security-headers";
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
                        .followRedirects(false)
                        .ignoreContentType(true)
                        .execute();
                log.debug("fetched URL: {} with status {}", url, resp.statusCode());
            } catch (Exception e) {
                log.warn("failed to fetch URL: {}", url, e);
                continue;
            }

            for (HeaderRule rule : RULES) {
                if (url.startsWith("http://") && rule.requiresHttps) continue;
                String headerValue = resp.header(rule.headerName);

                boolean missing = headerValue == null;
                boolean invalid = !missing && !rule.valueIsValid.test(headerValue);

                if (!missing && !invalid) continue;

                String title = missing
                        ? "Missing security header: " + rule.headerName
                        : "Weak security header: " + rule.headerName;
                String note = missing
                        ? "Response did not include the " + rule.headerName + " header."
                        : "Response included " + rule.headerName + " but the value is not considered safe.";

                findings.add(new ScanFinding(
                        title,
                        rule.severity,
                        name(),
                        new FindingLocation(url, null),
                        rule.description,
                        rule.remediation,
                        null,
                        note
                ));
            }
        }

        return findings;
    }
}
