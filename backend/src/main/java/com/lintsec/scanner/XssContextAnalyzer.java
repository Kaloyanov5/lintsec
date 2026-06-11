package com.lintsec.scanner;

import com.lintsec.domain.Severity;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Pure helpers for context-aware reflected-XSS confirmation: classify where a plain canary lands in
 * a response, build the context-specific breakout payload, and confirm whether the breakout
 * metacharacters survived unencoded. Raw-string based (matches the browser's pre-parse view), no DOM
 * normalization. Public shared helper (consumed by ReflectedXssModule) + unit-tested, in the spirit
 * of the confirmInjection() pattern.
 */
public final class XssContextAnalyzer {
    private XssContextAnalyzer() {}

    /** A confirmed breakout: the severity to report and a human-readable reason for the finding note. */
    public record Breakout(Severity severity, String detail) {}

    private static final Set<String> URL_ATTRS =
            Set.of("href", "src", "action", "formaction", "poster", "xlink:href");

    /** Classify the context of the canary at {@code offset} in {@code body}. */
    public static ReflectionContext classify(String body, int offset) {
        if (body == null || offset < 0 || offset >= body.length()) return ReflectionContext.UNKNOWN;
        String lower = body.toLowerCase(Locale.ROOT);

        // Raw-text / comment enclosures take priority (order: script, style, comment).
        if (enclosedIn(lower, offset, "<script", "</script")) return ReflectionContext.SCRIPT;
        if (enclosedIn(lower, offset, "<style", "</style")) return ReflectionContext.STYLE;
        if (enclosedIn(lower, offset, "<!--", "-->")) return ReflectionContext.COMMENT;

        // Inside an open tag if the nearest '<' before us is later than the nearest '>'.
        int lt = body.lastIndexOf('<', offset - 1);
        int gt = body.lastIndexOf('>', offset - 1);
        if (lt > gt) return classifyInsideTag(body, lt, offset);

        return ReflectionContext.HTML_TEXT;
    }

    /** True if the last {@code open} before {@code offset} has no {@code close} between it and offset. */
    private static boolean enclosedIn(String lower, int offset, String open, String close) {
        int o = lower.lastIndexOf(open, offset - 1);
        if (o < 0) return false;
        int c = lower.indexOf(close, o + open.length());
        return c < 0 || c >= offset;
    }

    /** We are between a '<' (at {@code tagStart}) and {@code offset} with no intervening '>'. */
    private static ReflectionContext classifyInsideTag(String body, int tagStart, int offset) {
        char quote = 0;          // open quote char, or 0
        boolean afterEquals = false;
        int eqAt = -1;           // '=' that opened the value we are in
        for (int i = tagStart + 1; i < offset; i++) {
            char ch = body.charAt(i);
            if (quote != 0) {
                if (ch == quote) { quote = 0; afterEquals = false; }
                continue;
            }
            switch (ch) {
                case '"', '\'' -> { if (afterEquals) quote = ch; }
                case '=' -> { afterEquals = true; eqAt = i; }
                default -> { if (Character.isWhitespace(ch)) afterEquals = false; }
            }
        }
        if (quote == '"') return urlRefine(body, eqAt, ReflectionContext.ATTR_DOUBLE);
        if (quote == '\'') return urlRefine(body, eqAt, ReflectionContext.ATTR_SINGLE);
        if (afterEquals) return urlRefine(body, eqAt, ReflectionContext.ATTR_UNQUOTED);
        return ReflectionContext.TAG_NAME;
    }

    /** If the attribute whose value we are in is URL-bearing (href/src/...), upgrade to ATTR_URL. */
    private static ReflectionContext urlRefine(String body, int eqAt, ReflectionContext attrCtx) {
        if (eqAt < 0) return attrCtx;
        int end = eqAt;
        while (end > 0 && Character.isWhitespace(body.charAt(end - 1))) end--;
        int start = end;
        while (start > 0) {
            char c = body.charAt(start - 1);
            if (Character.isWhitespace(c) || c == '<' || c == '"' || c == '\'') break;
            start--;
        }
        String name = body.substring(start, end).toLowerCase(Locale.ROOT);
        return URL_ATTRS.contains(name) ? ReflectionContext.ATTR_URL : attrCtx;
    }

    /** The Probe-2 injection value for {@code ctx}, embedding the shared {@code lintsec<nonce>} marker. */
    public static String breakoutPayload(ReflectionContext ctx, String nonce) {
        String marker = "lintsec" + nonce;
        // Note: the ATTR_UNQUOTED breakout relies on a raw space surviving. When this payload is sent
        // as a URL query value the space is encoded as '+'; servers that don't decode '+' back to a
        // space in query strings will suppress this (a conservative false negative, never a false positive).
        return switch (ctx) {
            case HTML_TEXT, TAG_NAME, UNKNOWN -> "<" + marker + ">";
            case ATTR_DOUBLE -> marker + "\"x";
            case ATTR_SINGLE -> marker + "'x";
            case ATTR_UNQUOTED -> marker + " x";
            case SCRIPT -> "</script><" + marker + ">";
            case STYLE -> "</style><" + marker + ">";
            case COMMENT -> "--><" + marker + ">";
            case ATTR_URL -> "javascript:" + marker;
        };
    }

    /**
     * Confirm the Probe-2 breakout: the context's distinguishing metacharacters must reflect raw
     * (unencoded) adjacent to the marker. Returns the severity + reason, or empty when encoded/absent.
     */
    public static Optional<Breakout> confirmBreakout(ReflectionContext ctx, String body, String nonce) {
        if (body == null) return Optional.empty();
        String marker = "lintsec" + nonce;
        return switch (ctx) {
            case HTML_TEXT, TAG_NAME, UNKNOWN -> hitIf(body.contains("<" + marker),
                    Severity.HIGH, "raw '<' before the canary breaks into HTML");
            case ATTR_DOUBLE -> hitIf(body.contains(marker + "\""),
                    Severity.HIGH, "raw '\"' after the canary breaks out of the double-quoted attribute");
            case ATTR_SINGLE -> hitIf(body.contains(marker + "'"),
                    Severity.HIGH, "raw ''' after the canary breaks out of the single-quoted attribute");
            case ATTR_UNQUOTED -> hitIf(body.contains(marker + " "),
                    Severity.HIGH, "raw space after the canary allows adding an event-handler attribute");
            case SCRIPT -> hitIf(body.contains("</script><" + marker),
                    Severity.HIGH, "raw '</script>' before the canary closes the script element");
            case STYLE -> hitIf(body.contains("</style><" + marker),
                    Severity.MEDIUM, "raw '</style>' before the canary breaks out of the style element");
            case COMMENT -> hitIf(body.contains("--><" + marker),
                    Severity.HIGH, "raw '-->' before the canary escapes the HTML comment");
            case ATTR_URL -> hitIf(body.contains("javascript:" + marker),
                    Severity.HIGH, "raw 'javascript:' scheme reflected in a URL attribute executes on navigation");
        };
    }

    private static Optional<Breakout> hitIf(boolean condition, Severity severity, String detail) {
        return condition ? Optional.of(new Breakout(severity, detail)) : Optional.empty();
    }
}
