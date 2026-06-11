package com.lintsec.scanner;

import java.util.Locale;
import java.util.Set;

/**
 * Pure helpers for context-aware reflected-XSS confirmation: classify where a plain canary lands in
 * a response, build the context-specific breakout payload, and confirm whether the breakout
 * metacharacters survived unencoded. Raw-string based (matches the browser's pre-parse view), no DOM
 * normalization. Package-private + unit-tested, mirroring the confirmInjection() pattern.
 */
final class XssContextAnalyzer {
    private XssContextAnalyzer() {}

    /** A confirmed breakout: the severity to report and a human-readable reason for the finding note. */
    record Breakout(com.lintsec.domain.Severity severity, String detail) {}

    private static final Set<String> URL_ATTRS =
            Set.of("href", "src", "action", "formaction", "poster", "xlink:href");

    /** Classify the context of the canary at {@code offset} in {@code body}. */
    static ReflectionContext classify(String body, int offset) {
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
}
