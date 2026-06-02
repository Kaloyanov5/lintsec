package com.lintsec.crawler;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Establishes an authenticated {@link AuthSession} for a scan, either by submitting an HTML
 * login form (scraping any hidden CSRF token first) or by accepting a pasted session cookie.
 * Runs once, before the crawl. Throws {@link AuthenticationException} if login cannot be
 * verified, so the scan fails loudly rather than silently scanning logged-out.
 */
@Component
public class FormLoginAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(FormLoginAuthenticator.class);

    private final int timeoutMs;
    private final String userAgent;

    public FormLoginAuthenticator() {
        this.timeoutMs = 10_000;
        this.userAgent = "LintSec-Scanner/1.0";
    }

    public AuthSession authenticate(LoginConfig config) {
        if (config.usesCookieInjection()) {
            return new AuthSession(parseCookieHeader(config.sessionCookie()));
        }
        return formLogin(config);
    }

    private AuthSession formLogin(LoginConfig config) {
        // 1. GET the login page: capture initial cookies + hidden form fields (CSRF tokens).
        Connection.Response loginPage;
        try {
            loginPage = Jsoup.connect(config.loginUrl())
                    .userAgent(userAgent)
                    .timeout(timeoutMs)
                    .method(Connection.Method.GET)
                    .ignoreHttpErrors(true)
                    .execute();
        } catch (Exception e) {
            throw new AuthenticationException("could not load login page: " + e.getMessage());
        }

        Map<String, String> cookies = new HashMap<>(loginPage.cookies());
        Map<String, String> formData = new LinkedHashMap<>();
        try {
            Document doc = loginPage.parse();
            for (Element hidden : doc.select("input[type=hidden][name]")) {
                formData.put(hidden.attr("name"), hidden.attr("value"));
            }
        } catch (Exception e) {
            log.debug("login page parse failed (no hidden fields scraped): {}", e.getMessage());
        }

        // 2. Overlay credentials.
        formData.put(config.usernameField(), config.username());
        formData.put(config.passwordField(), config.password());

        // 3. POST credentials, following redirects so the session cookie on the post-login
        //    redirect is captured.
        Connection.Response loginResult;
        try {
            loginResult = Jsoup.connect(config.loginUrl())
                    .userAgent(userAgent)
                    .timeout(timeoutMs)
                    .cookies(cookies)
                    .data(formData)
                    .method(Connection.Method.POST)
                    .ignoreHttpErrors(true)
                    .followRedirects(true)
                    .execute();
        } catch (Exception e) {
            throw new AuthenticationException("login request failed: " + e.getMessage());
        }

        Map<String, String> sessionCookies = new HashMap<>(cookies);
        sessionCookies.putAll(loginResult.cookies());

        // 4. Verify.
        int status = loginResult.statusCode();
        if (status == 401 || status == 403) {
            throw new AuthenticationException("login rejected (HTTP " + status + ")");
        }
        if (sessionCookies.isEmpty()) {
            throw new AuthenticationException("login produced no session cookie");
        }
        String check = config.successCheck();
        if (check != null && !check.isBlank()) {
            String body;
            try {
                body = loginResult.body();
            } catch (Exception e) {
                body = "";
            }
            if (body == null || !body.contains(check)) {
                throw new AuthenticationException("login success indicator not found in response");
            }
        }

        log.info("login OK for {} ({} session cookies)", config.loginUrl(), sessionCookies.size());
        return new AuthSession(sessionCookies);
    }

    /** Parse a raw "k=v; k2=v2" cookie header into a map. */
    private static Map<String, String> parseCookieHeader(String raw) {
        Map<String, String> cookies = new HashMap<>();
        for (String pair : raw.split(";")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                cookies.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
            }
        }
        if (cookies.isEmpty()) {
            throw new AuthenticationException("session cookie could not be parsed");
        }
        return cookies;
    }
}
