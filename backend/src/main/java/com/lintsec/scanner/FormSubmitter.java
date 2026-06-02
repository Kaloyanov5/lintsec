package com.lintsec.scanner;

import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.crawler.FormField;
import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Shared form-submission machinery for active scanner modules.
 *
 * <p>The crawler discovers {@link DiscoveredForm}s; modules use this helper to submit one with a
 * payload injected into a single target field while the remaining fields carry benign filler (or
 * their discovered default value, so hidden CSRF tokens and preset selects survive the round-trip).
 * This is the form-vector analogue of {@link UrlParams} for query-string probing.
 */
public final class FormSubmitter {
    private static final Logger log = LoggerFactory.getLogger(FormSubmitter.class);

    // Free-text-like inputs worth injecting a payload into. Hidden/checkbox/radio/file fields
    // are filled but never targeted; submit/button/reset/image are dropped at extraction time.
    private static final Set<String> FUZZABLE_TYPES = Set.of(
            "text", "search", "url", "email", "tel", "password", "textarea", ""
    );

    private FormSubmitter() {}

    /** Names of the fields in this form that are worth injecting a payload into. */
    public static List<String> fuzzableFields(DiscoveredForm form) {
        List<String> names = new ArrayList<>();
        for (FormField field : form.fields()) {
            if (FUZZABLE_TYPES.contains(field.type().toLowerCase())) {
                names.add(field.name());
            }
        }
        return names;
    }

    /**
     * Submit {@code form} with {@code payload} placed in {@code targetField}; all other fields are
     * filled with benign values. Returns the raw response, or empty on any I/O failure (fail-soft).
     */
    public static Optional<Connection.Response> submit(
            DiscoveredForm form,
            String targetField,
            String payload,
            ScanContext context,
            boolean followRedirects) {

        Map<String, String> data = new LinkedHashMap<>();
        for (FormField field : form.fields()) {
            data.put(field.name(), field.name().equals(targetField) ? payload : fillerFor(field));
        }

        // HTML forms only support GET and POST; treat anything else as POST.
        Connection.Method method = "GET".equalsIgnoreCase(form.method())
                ? Connection.Method.GET
                : Connection.Method.POST;

        try {
            Connection.Response resp = context.openConnection(form.action())
                    .method(method)
                    .data(data)
                    .ignoreHttpErrors(true)
                    .followRedirects(followRedirects)
                    .ignoreContentType(true)
                    .execute();
            log.debug("submitted {} form to {} (field {}) -> {}",
                    method, form.action(), targetField, resp.statusCode());
            return Optional.of(resp);
        } catch (Exception e) {
            log.warn("form submit failed for {} field {}: {}", form.action(), targetField, e.getMessage());
            return Optional.empty();
        }
    }

    private static String fillerFor(FormField field) {
        // Preserve hidden tokens, preset hidden values, and default selections.
        if (field.value() != null && !field.value().isBlank()) {
            return field.value();
        }
        return switch (field.type().toLowerCase()) {
            case "email" -> "lintsec@example.invalid";
            case "number", "range" -> "1";
            case "url" -> "https://example.invalid/";
            case "tel" -> "1000000000";
            case "password" -> "Lintsec!Test123";
            default -> "lintsec";
        };
    }
}
