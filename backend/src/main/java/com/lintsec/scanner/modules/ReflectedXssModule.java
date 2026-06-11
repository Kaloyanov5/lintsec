package com.lintsec.scanner.modules;

import com.lintsec.crawler.CrawlResult;
import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.scanner.*;
import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public final class ReflectedXssModule implements ScannerModule {
    private static final Logger log = LoggerFactory.getLogger(ReflectedXssModule.class);

    @Override
    public String name() {
        return "reflected-xss";
    }

    @Override
    public List<ScanFinding> scan(CrawlResult crawlResult, ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        String nonce = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String plain = PayloadCatalog.payloadFor(PayloadId.XSS_CANARY_PLAIN, nonce);

        // URL-parameter vector.
        for (String url : crawlResult.visitedUrls()) {
            List<Map.Entry<String, String>> params = UrlParams.parseQueryParameters(URI.create(url));
            if (params.isEmpty()) continue;

            for (Map.Entry<String, String> entry : params) {
                String paramName = entry.getKey();
                String locateBody = fetchBody(context, UrlParams.replaceQueryParameters(url, paramName, plain));
                for (ReflectionContext ctx : distinctContexts(locateBody, plain)) {
                    String probe = XssContextAnalyzer.breakoutPayload(ctx, nonce);
                    String breakoutBody = fetchBody(context, UrlParams.replaceQueryParameters(url, paramName, probe));
                    XssContextAnalyzer.confirmBreakout(ctx, breakoutBody, nonce).ifPresent(b ->
                            findings.add(finding(new FindingLocation(url, paramName), "parameter: " + paramName, ctx, b)));
                }
            }
        }

        // Form vector: submit each discovered form with the payload in one field at a time.
        for (DiscoveredForm form : crawlResult.forms()) {
            for (String field : FormSubmitter.fuzzableFields(form)) {
                String locateBody = FormSubmitter.submit(form, field, plain, context, true)
                        .map(Connection.Response::body).orElse(null);
                for (ReflectionContext ctx : distinctContexts(locateBody, plain)) {
                    String probe = XssContextAnalyzer.breakoutPayload(ctx, nonce);
                    String breakoutBody = FormSubmitter.submit(form, field, probe, context, true)
                            .map(Connection.Response::body).orElse(null);
                    XssContextAnalyzer.confirmBreakout(ctx, breakoutBody, nonce).ifPresent(b ->
                            findings.add(finding(new FindingLocation(form.action(), field), "form field: " + field, ctx, b)));
                }
            }
        }

        return findings;
    }

    /** Distinct contexts across every reflection of {@code canary} in {@code body}. */
    private static List<ReflectionContext> distinctContexts(String body, String canary) {
        if (body == null) return List.of();
        LinkedHashSet<ReflectionContext> contexts = new LinkedHashSet<>();
        int from = 0, idx;
        while ((idx = body.indexOf(canary, from)) >= 0) {
            contexts.add(XssContextAnalyzer.classify(body, idx));
            from = idx + canary.length();
        }
        return new ArrayList<>(contexts);
    }

    private static String fetchBody(ScanContext context, String url) {
        try {
            return context.openConnection(url)
                    .method(Connection.Method.GET)
                    .ignoreHttpErrors(true)
                    .followRedirects(false)
                    .ignoreContentType(true)
                    .execute()
                    .body();
        } catch (Exception e) {
            log.warn("reflected-xss fetch failed for {}: {}", url, e.getMessage());
            return null;
        }
    }

    private ScanFinding finding(FindingLocation location, String vector, ReflectionContext ctx,
                                XssContextAnalyzer.Breakout breakout) {
        String where = describe(ctx);
        return new ScanFinding(
                "Reflected XSS via " + vector,
                breakout.severity(),
                name(),
                location,
                "A " + vector + " is reflected into the response in a " + where + " context without adequate output "
                        + "encoding. An attacker can craft a request that injects markup or script executing in the "
                        + "victim's browser, leading to session theft, credential harvesting, or actions on the user's behalf.",
                "Context-appropriate output encoding (HTML-encode for tag content, attribute-encode for attribute "
                        + "values, JS-encode for script context, and validate/scheme-check URL attributes). Most templating "
                        + "engines do this by default — ensure unsafe APIs like Thymeleaf's th:utext or React's "
                        + "dangerouslySetInnerHTML are not used with user input.",
                PayloadId.XSS_CANARY_REFLECTED,
                "Canary reflected in " + where + " context; " + breakout.detail() + "."
        );
    }

    private static String describe(ReflectionContext ctx) {
        return switch (ctx) {
            case HTML_TEXT -> "HTML body";
            case ATTR_DOUBLE -> "double-quoted attribute";
            case ATTR_SINGLE -> "single-quoted attribute";
            case ATTR_UNQUOTED -> "unquoted attribute";
            case ATTR_URL -> "URL attribute";
            case SCRIPT -> "inline <script>";
            case STYLE -> "inline <style>";
            case COMMENT -> "HTML comment";
            case TAG_NAME -> "tag-name";
            case UNKNOWN -> "unclassified";
        };
    }
}
