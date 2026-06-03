package com.lintsec.scanner;

import com.lintsec.crawler.DiscoveredForm;
import com.lintsec.crawler.FormField;
import org.jsoup.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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

    // Action-URL substrings marking forms that control the scanner's own session/security/setup.
    // Submitting these mid-scan sabotages the rest of the run — e.g. DVWA's /security.php form
    // coerces an unknown level to "impossible", hardening every subsequent probe in the shared
    // AuthSession. Mirrors the Crawler's logout-link skip, but for active submission.
    private static final Set<String> STATE_CHANGING_ACTION_MARKERS = Set.of(
            "logout", "signout", "sign-out", "logoff",
            "login", "signin", "sign-in", "security", "setup"
    );

    private FormSubmitter() {}

    /**
     * Whether this form must NOT be actively fuzzed because submitting it would alter the scan's
     * own session, security level, or credentials. True if the action targets a session/security/
     * setup endpoint, or the form carries a password field (login / password-change). Passive
     * modules still see these forms via {@code crawlResult.forms()}; only active submission skips.
     */
    static boolean isStateChangingForm(DiscoveredForm form) {
        String action = form.action() == null ? "" : form.action().toLowerCase(Locale.ROOT);
        for (String marker : STATE_CHANGING_ACTION_MARKERS) {
            if (action.contains(marker)) return true;
        }
        for (FormField field : form.fields()) {
            if ("password".equalsIgnoreCase(field.type())) return true;
        }
        return false;
    }

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

        // Never fuzz forms that control our own session/security/credentials — submitting them
        // poisons the rest of the scan (e.g. flips DVWA's security level to "impossible").
        if (isStateChangingForm(form)) {
            log.debug("skipping state-changing form {} — not fuzzing (would alter scan session/credentials)",
                    form.action());
            return Optional.empty();
        }

        // For token-bearing forms, re-fetch a fresh single-use token immediately before submitting.
        Map<String, String> freshHidden =
                FormStateRefresher.freshHiddenValues(form, context).orElse(Map.of());
        Map<String, String> data = buildSubmissionData(form, targetField, payload, freshHidden);

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

    /**
     * Build the submitted field map: {@code payload} in {@code targetField}; fresh hidden
     * values where supplied; benign fillers (or discovered defaults) elsewhere; plus the
     * form's submit control so handlers guarded by {@code isset($_POST['Submit'])} fire.
     */
    static Map<String, String> buildSubmissionData(
            DiscoveredForm form,
            String targetField,
            String payload,
            Map<String, String> freshHidden) {

        Map<String, String> data = new LinkedHashMap<>();
        for (FormField field : form.fields()) {
            String name = field.name();
            // Target field wins over a fresh value on purpose: fuzzing that field is the point.
            if (name.equals(targetField)) {
                data.put(name, payload);
            } else if (freshHidden.containsKey(name)) {
                data.put(name, freshHidden.get(name));
            } else {
                data.put(name, fillerFor(field));
            }
        }

        FormField submit = form.submitControl();
        if (submit != null && !submit.name().isBlank()) {
            if ("image".equalsIgnoreCase(submit.type())) {
                data.put(submit.name() + ".x", "1");
                data.put(submit.name() + ".y", "1");
            } else {
                String value = (submit.value() == null || submit.value().isBlank())
                        ? submit.name()
                        : submit.value();
                data.put(submit.name(), value);
            }
        }
        return data;
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
