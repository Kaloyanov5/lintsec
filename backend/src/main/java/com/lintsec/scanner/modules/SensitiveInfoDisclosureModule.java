package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.FindingLocation;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScannerModule;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public final class SensitiveInfoDisclosureModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(SensitiveInfoDisclosureModule.class);

    private record DisclosureRule(
            String ruleName,         // e.g. "AWS_ACCESS_KEY", used in title and evidenceNote
            Pattern pattern,         // pre-compiled regex
            Severity severity,
            String description,
            String remediation
    ) {}

    private static final List<DisclosureRule> RULES = List.of(
            new DisclosureRule(
                    "AWS_ACCESS_KEY",
                    Pattern.compile("AKIA[0-9A-Z]{16}"),
                    Severity.HIGH,
                    "An AWS access key ID pattern was found in the response body.",
                    "Rotate the key immediately and audit access. Move secrets to environment variables or a secrets manager; never serve them to clients."
            ), new DisclosureRule(
                    "PRIVATE_KEY_BLOCK",
                    Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
                    Severity.CRITICAL,
                    "A PEM-encoded private key block was found in the response body. If this key is real, the host is compromised — any TLS, SSH, or signing operation backed by this key must be considered untrustworthy.",
                    "Treat the key as compromised. Revoke and rotate it immediately. Audit how it leaked (config file served by mistake? backup directory exposed? .git in webroot?) and remove the source."
            ), new DisclosureRule(
                    "JWT_TOKEN",
                    Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"),
                    Severity.MEDIUM,
                    "A JSON Web Token pattern was found in the response body. JWTs in HTML responses can leak session identity to anyone viewing the page (including via screenshots, browser cache, or logs).",
                    "Investigate why a JWT is being rendered into HTML. Tokens belong in HttpOnly cookies or Authorization headers, not response bodies. Note: this check has a high false-positive rate — verify manually before treating as a vulnerability."
            ), new DisclosureRule(
                    "JAVA_STACK_TRACE",
                    Pattern.compile("\\tat [\\w.$]+\\([\\w]+\\.java:\\d+\\)"),
                    Severity.MEDIUM,
                    "A Java stack trace was found in the response body. Stack traces leak internal class names, file paths, and dependency versions — useful reconnaissance for an attacker probing for exploits.",
                    "Configure a global exception handler that returns a generic error page in production. Log the full trace server-side, not client-side."
            ), new DisclosureRule(
                    "SPRING_WHITELABEL_ERROR",
                    Pattern.compile("Whitelabel Error Page"),
                    Severity.LOW,
                    "The default Spring Boot Whitelabel error page was rendered, indicating that no custom error handler is configured. Reveals the framework and confirms the app is reachable in an error state.",
                    "Add a custom error controller or configure server.error.whitelabel.enabled=false and a custom error template."
            )
    );

    @Override
    public String name() {
        return "sensitive-info-disclosure";
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
                        .execute();
                log.debug("fetched URL: {} with status {}", url, resp.statusCode());
            } catch (Exception e) {
                log.warn("failed to fetch URL: {}", url, e);
                continue;
            }
            String body = resp.body();

            for (DisclosureRule rule : RULES) {
                Matcher m = rule.pattern.matcher(body);
                while (m.find()) {
                    findings.add(new ScanFinding(
                            "Sensitive info disclosure: " + rule.ruleName,
                            rule.severity,
                            name(),
                            new FindingLocation(url, null),
                            rule.description,
                            rule.remediation,
                            null,
                            "Pattern " + rule.ruleName + " matched at offset " + m.start()
                    ));
                }
            }
        }

        return findings;
    }
}
