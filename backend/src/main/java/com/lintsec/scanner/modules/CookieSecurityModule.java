package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.domain.Severity;
import com.lintsec.scanner.FindingLocation;
import com.lintsec.scanner.ScanContext;
import com.lintsec.scanner.ScanFinding;
import com.lintsec.scanner.ScannerModule;
import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public final class CookieSecurityModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(CookieSecurityModule.class);

    private static final Set<String> SESSION_COOKIE_NAME_PATTERNS = Set.of(
            "session", "sess", "sid", "auth", "token", "jwt", "csrf", "xsrf"
    );

    private record ParsedCookie(
            String name,
            Set<String> attributes,
            Map<String, String> attributeValues
    ) {}

    @Override
    public String name() {
        return "cookie-security";
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

            List<ParsedCookie> cookies = resp.headers("Set-Cookie").stream().map(CookieSecurityModule::parse).toList();
            for (ParsedCookie cookie : cookies) {
                if (cookie == null) continue;

                boolean isHttps = url.startsWith("https://");
                boolean hasSecure = cookie.attributes.contains("secure");
                boolean hasHttpOnly = cookie.attributes.contains("httponly");
                boolean hasSameSite = cookie.attributes.contains("samesite");
                String sameSiteValue = cookie.attributeValues().get("samesite");

                if (isHttps && !hasSecure) {
                    findings.add(new ScanFinding(
                            "Cookie missing Secure flag",
                            Severity.HIGH,
                            name(),
                            new FindingLocation(url, cookie.name()),
                            "Cookies without the Secure attribute are sent over unencrypted HTTP, allowing network attackers to intercept session tokens or sensitive data.",
                            "Add the 'Secure' attribute to all cookies set on HTTPS responses. In Spring Boot: server.servlet.session.cookie.secure=true.",
                            null,
                            "Set-Cookie for '" + cookie.name() + "' did not include the Secure attribute."
                    ));
                }

                if (!hasHttpOnly && looksLikeSession(cookie.name())) {
                    findings.add(new ScanFinding(
                            "Session-like cookie missing HttpOnly flag",
                            Severity.MEDIUM,
                            name(),
                            new FindingLocation(url, cookie.name()),
                            "Session and authentication cookies without HttpOnly can be read from JavaScript via document.cookie. If the site has any XSS, an attacker can exfiltrate the session token and hijack the user's account.",
                            "Set 'HttpOnly' on session, auth, CSRF, and similar cookies. In Spring Boot: server.servlet.session.cookie.http-only=true (the default — confirm it has not been overridden).",
                            null,
                            "Set-Cookie for '" + cookie.name() + "' did not include the HttpOnly attribute."
                    ));
                }

                if (!hasSameSite) {
                    findings.add(new ScanFinding(
                            "Cookie missing SameSite flag",
                            Severity.LOW,
                            name(),
                            new FindingLocation(url, cookie.name()),
                            "Without SameSite, the cookie is sent on cross-site requests, weakening CSRF protection. Modern browsers default to Lax but explicit declaration is more reliable across older browser versions and clearer to readers of the response.",
                            "Set SameSite=Lax for most cookies, or Strict for high-value cookies that should never travel cross-site. Use SameSite=None only when third-party embedding is required, and always pair it with Secure.",
                            null,
                            "Set-Cookie for '" + cookie.name() + "' did not include the SameSite attribute."
                    ));
                }

                if (sameSiteValue != null && sameSiteValue.equalsIgnoreCase("None") && !hasSecure) {
                    findings.add(new ScanFinding(
                            "Cookie missing Secure flag with SameSite=None",
                            Severity.HIGH,
                            name(),
                            new FindingLocation(url, cookie.name()),
                            "SameSite=None signals that the cookie is allowed in cross-site contexts; Chrome 80+, Firefox 96+, and Safari silently drop such cookies unless they also carry the Secure attribute. The cookie is therefore either broken in modern browsers or set on an insecure transport — both are bad outcomes.",
                            "If the cookie genuinely needs cross-site availability, pair SameSite=None with Secure. Otherwise switch to SameSite=Lax and drop the None value.",
                            null,
                            "Set-Cookie for '" + cookie.name() + "' did not include the Secure attribute."
                    ));
                }
            }
        }
        return findings;
    }

    private static ParsedCookie parse(String setCookieValue) {
        if (setCookieValue == null || setCookieValue.isBlank()) return null;

        String[] parts = setCookieValue.split(";");
        String namePart = parts[0].trim();
        int eqIndex = namePart.indexOf('=');
        if (eqIndex <= 0) return null;

        String cookieName = namePart.substring(0, eqIndex).trim();
        Set<String> attributes = new java.util.LinkedHashSet<>();
        Map<String, String> attributeValues = new java.util.HashMap<>();

        for (int i = 1; i < parts.length; i++) {
            String attribute = parts[i].trim();
            if (attribute.isEmpty()) continue;

            int attrEqIndex = attribute.indexOf('=');
            if (attrEqIndex > 0) {
                String attrName = attribute.substring(0, attrEqIndex).trim().toLowerCase(java.util.Locale.ROOT);
                String attrValue = attribute.substring(attrEqIndex + 1).trim();
                attributes.add(attrName);
                attributeValues.put(attrName, attrValue);
            } else attributes.add(attribute.toLowerCase(java.util.Locale.ROOT));
        }
        return new ParsedCookie(cookieName, attributes, attributeValues);
    }

    private static boolean looksLikeSession(String cookieName) {
        if (cookieName == null) return false;

        String lowerName = cookieName.toLowerCase(java.util.Locale.ROOT);
        for (String pattern : SESSION_COOKIE_NAME_PATTERNS) if (lowerName.contains(pattern)) return true;
        return false;
    }
}
