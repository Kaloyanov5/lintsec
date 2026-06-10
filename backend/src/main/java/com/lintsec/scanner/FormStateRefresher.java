package com.lintsec.scanner;

import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.crawler.FormExtractor;
import com.lintsec.crawler.FormField;
import com.lintsec.crawler.GuardedHttp;
import com.lintsec.crawler.TargetGuard;
import org.jsoup.Connection;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Supplies fresh hidden-field values (chiefly single-use anti-CSRF tokens) for a form
 * immediately before it is submitted. Anti-CSRF tokens captured at crawl time are stale by
 * submission time, so token-protected forms would otherwise reject every fuzzing request
 * before the payload reaches a sink.
 *
 * <p>Only token-bearing forms incur a re-fetch; token-less forms return empty (zero extra
 * requests). Fail-soft: any failure returns empty and the caller submits with crawl-time
 * values rather than aborting the scan.
 */
public final class FormStateRefresher {
    private static final Logger log = LoggerFactory.getLogger(FormStateRefresher.class);

    private FormStateRefresher() {}

    /**
     * Re-GET the form's page and return its current hidden-field values, keyed by field name.
     * Empty if the form carries no token-looking field, or on any fetch/parse/match failure.
     */
    public static Optional<Map<String, String>> freshHiddenValues(DiscoveredForm form, ScanContext context) {
        if (!hasTokenField(form)) return Optional.empty();
        if (!TargetGuard.isAllowed(form.pageUrl())) return Optional.empty();
        try {
            Optional<Connection.Response> respOpt = GuardedHttp.execute(context.openConnection(form.pageUrl())
                    .method(Connection.Method.GET)
                    .ignoreHttpErrors(true)
                    .ignoreContentType(true));
            if (respOpt.isEmpty()) return Optional.empty();
            Document doc = respOpt.get().parse();
            Optional<Map<String, String>> fresh = extractFreshValues(doc, form);
            if (fresh.isEmpty()) {
                log.debug("token refresh: form {} not found on re-fetch of {}", form.signature(), form.pageUrl());
            }
            return fresh;
        } catch (Exception e) {
            log.debug("token refresh failed for {}: {}", form.pageUrl(), e.getMessage());
            return Optional.empty();
        }
    }

    /** True if any of the form's fields has a name that looks like an anti-CSRF token. */
    static boolean hasTokenField(DiscoveredForm form) {
        for (FormField field : form.fields()) {
            if (CsrfTokens.looksLikeTokenName(field.name())) return true;
        }
        return false;
    }

    /**
     * Pure: from a freshly fetched document, find the form matching {@code original} by
     * signature and return its hidden fields' current values. Empty if no form matches.
     */
    static Optional<Map<String, String>> extractFreshValues(Document refetched, DiscoveredForm original) {
        String wanted = original.signature();
        // First signature match wins; ambiguous when a page hosts multiple structurally
        // identical forms (same method/action/field-names), but fail-soft tolerates a wrong token.
        for (DiscoveredForm candidate : FormExtractor.extractForms(refetched)) {
            if (candidate.signature().equals(wanted)) {
                Map<String, String> hidden = new LinkedHashMap<>();
                for (FormField field : candidate.fields()) {
                    if ("hidden".equalsIgnoreCase(field.type())) {
                        hidden.put(field.name(), field.value());
                    }
                }
                return Optional.of(hidden);
            }
        }
        return Optional.empty();
    }
}
