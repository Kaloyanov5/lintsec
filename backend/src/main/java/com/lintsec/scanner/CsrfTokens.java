package com.lintsec.scanner;

import java.util.Locale;
import java.util.Set;

/**
 * Shared heuristic for recognising anti-CSRF token field names across common frameworks
 * (Spring Security _csrf, Django csrfmiddlewaretoken, Rails authenticity_token, ASP.NET
 * __RequestVerificationToken, generic nonce/xsrf). Used by MissingCsrfTokenModule (to flag
 * missing tokens) and FormStateRefresher (to decide which forms need a fresh-token re-fetch).
 */
public final class CsrfTokens {

    private static final Set<String> TOKEN_NAME_PATTERNS = Set.of(
            "csrf", "xsrf", "token", "authenticity", "nonce", "verification"
    );

    private CsrfTokens() {}

    public static boolean looksLikeTokenName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String pattern : TOKEN_NAME_PATTERNS) {
            if (lower.contains(pattern)) return true;
        }
        return false;
    }
}
