# Context-Aware Reflected XSS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `ReflectedXssModule`'s single literal-`<…>` check with a two-probe, context-classified confirmation that catches attribute / `<script>` / comment / URL-scheme reflections while reporting only confirmed-exploitable cases.

**Architecture:** A new pure `XssContextAnalyzer` (raw-string-scan classifier + breakout-payload builder + breakout confirmer, all package-private static methods with unit tests), a new `ReflectionContext` enum, one new `PayloadId`/`PayloadCatalog` entry, and a rewrite of `ReflectedXssModule` to drive the locate→classify→breakout→confirm flow over both the URL-param and form vectors.

**Tech Stack:** Java 21 (records, switch expressions), Spring Boot, JSoup `Connection`, JUnit 5 (`org.junit.jupiter`). Build/test: `./mvnw.cmd -o test` from `backend/` (offline OK for tests).

**Spec:** `backend/docs/superpowers/specs/2026-06-11-reflected-xss-context-awareness-design.md`

**Note on one deliberate deviation from the spec:** the spec suggested reusing `XSS_CANARY_REFLECTED` (`<lintsec_canary_{nonce}>`) as the HTML-text breakout payload. To keep a single consistent marker across both probes (`lintsec{nonce}`), the breakout payloads are instead built entirely inside `XssContextAnalyzer.breakoutPayload`. `XSS_CANARY_REFLECTED` is retained only as the finding's `evidenceRef` tag and its `descriptionFor` text. Behavior and the reported contract are unchanged.

---

## File Structure

- **Create** `src/main/java/com/lintsec/scanner/ReflectionContext.java` — enum of reflection contexts.
- **Create** `src/main/java/com/lintsec/scanner/XssContextAnalyzer.java` — pure classifier + breakout builder + confirmer (the only new logic; fully unit-tested).
- **Create** `src/test/java/com/lintsec/scanner/XssContextAnalyzerTest.java` — unit tests.
- **Modify** `src/main/java/com/lintsec/scanner/PayloadId.java` — add `XSS_CANARY_PLAIN`.
- **Modify** `src/main/java/com/lintsec/scanner/PayloadCatalog.java` — `payloadFor` + `descriptionFor` for `XSS_CANARY_PLAIN`.
- **Modify** `src/test/java/com/lintsec/scanner/PayloadCatalogTest.java` — assert the new payload string (only if the existing test enumerates payloads; check first).
- **Modify** `src/main/java/com/lintsec/scanner/modules/ReflectedXssModule.java` — rewrite `scan` to the two-probe flow.

---

## Task 1: `ReflectionContext` enum

**Files:**
- Create: `src/main/java/com/lintsec/scanner/ReflectionContext.java`

- [ ] **Step 1: Create the enum**

```java
package com.lintsec.scanner;

/** Where a reflected canary lands in the response, determining the breakout payload to confirm with. */
public enum ReflectionContext {
    HTML_TEXT,
    ATTR_DOUBLE,
    ATTR_SINGLE,
    ATTR_UNQUOTED,
    ATTR_URL,
    SCRIPT,
    STYLE,
    COMMENT,
    TAG_NAME,
    UNKNOWN
}
```

- [ ] **Step 2: Compile**

Run: `./mvnw.cmd -o -q compile`
Expected: BUILD SUCCESS (no test yet — this enum is exercised in Task 2).

- [ ] **Step 3: Commit**

```bash
git add backend/src/main/java/com/lintsec/scanner/ReflectionContext.java
git commit -m "feat(scan): add ReflectionContext enum for XSS context classification"
```

---

## Task 2: `XssContextAnalyzer` — classify

**Files:**
- Create: `src/main/java/com/lintsec/scanner/XssContextAnalyzer.java`
- Test: `src/test/java/com/lintsec/scanner/XssContextAnalyzerTest.java`

- [ ] **Step 1: Write the failing tests for `classify`**

```java
package com.lintsec.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XssContextAnalyzerTest {

    private static int at(String body, String canary) {
        return body.indexOf(canary);
    }

    @Test
    void classifiesHtmlBodyText() {
        String body = "<p>hello CANARY world</p>";
        assertEquals(ReflectionContext.HTML_TEXT, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesDoubleQuotedAttribute() {
        String body = "<input type=\"text\" value=\"CANARY\">";
        assertEquals(ReflectionContext.ATTR_DOUBLE, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesSingleQuotedAttribute() {
        String body = "<input value='CANARY'>";
        assertEquals(ReflectionContext.ATTR_SINGLE, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesUnquotedAttribute() {
        String body = "<input value=CANARY>";
        assertEquals(ReflectionContext.ATTR_UNQUOTED, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesUrlAttributeAsAttrUrl() {
        String body = "<a href=\"CANARY\">link</a>";
        assertEquals(ReflectionContext.ATTR_URL, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesInsideScript() {
        String body = "<script>var x = 'CANARY';</script>";
        assertEquals(ReflectionContext.SCRIPT, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesInsideStyle() {
        String body = "<style>.a{color:CANARY}</style>";
        assertEquals(ReflectionContext.STYLE, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesInsideComment() {
        String body = "<!-- note: CANARY -->";
        assertEquals(ReflectionContext.COMMENT, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void classifiesTagNamePosition() {
        String body = "<CANARY foo>";
        assertEquals(ReflectionContext.TAG_NAME, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void closedScriptBeforeReflectionIsNotScript() {
        String body = "<script>ok</script><p>CANARY</p>";
        assertEquals(ReflectionContext.HTML_TEXT, XssContextAnalyzer.classify(body, at(body, "CANARY")));
    }

    @Test
    void nullOrOutOfRangeIsUnknown() {
        assertEquals(ReflectionContext.UNKNOWN, XssContextAnalyzer.classify(null, 0));
        assertEquals(ReflectionContext.UNKNOWN, XssContextAnalyzer.classify("abc", 99));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./mvnw.cmd -o -q -Dtest=XssContextAnalyzerTest test`
Expected: COMPILATION FAILURE — `XssContextAnalyzer` does not exist yet.

- [ ] **Step 3: Implement `XssContextAnalyzer` with `classify`**

```java
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./mvnw.cmd -o -q -Dtest=XssContextAnalyzerTest test`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/src/main/java/com/lintsec/scanner/XssContextAnalyzer.java backend/src/test/java/com/lintsec/scanner/XssContextAnalyzerTest.java
git commit -m "feat(scan): classify reflected-XSS canary context"
```

---

## Task 3: `XssContextAnalyzer` — `breakoutPayload` + `confirmBreakout`

**Files:**
- Modify: `src/main/java/com/lintsec/scanner/XssContextAnalyzer.java`
- Test: `src/test/java/com/lintsec/scanner/XssContextAnalyzerTest.java`

- [ ] **Step 1: Add the failing tests**

Append these methods to `XssContextAnalyzerTest`:

```java
    @Test
    void breakoutPayloadsAreContextSpecific() {
        assertEquals("<lintsecN1>", XssContextAnalyzer.breakoutPayload(ReflectionContext.HTML_TEXT, "N1"));
        assertEquals("lintsecN1\"x", XssContextAnalyzer.breakoutPayload(ReflectionContext.ATTR_DOUBLE, "N1"));
        assertEquals("lintsecN1'x", XssContextAnalyzer.breakoutPayload(ReflectionContext.ATTR_SINGLE, "N1"));
        assertEquals("lintsecN1 x", XssContextAnalyzer.breakoutPayload(ReflectionContext.ATTR_UNQUOTED, "N1"));
        assertEquals("</script><lintsecN1>", XssContextAnalyzer.breakoutPayload(ReflectionContext.SCRIPT, "N1"));
        assertEquals("</style><lintsecN1>", XssContextAnalyzer.breakoutPayload(ReflectionContext.STYLE, "N1"));
        assertEquals("--><lintsecN1>", XssContextAnalyzer.breakoutPayload(ReflectionContext.COMMENT, "N1"));
        assertEquals("javascript:lintsecN1", XssContextAnalyzer.breakoutPayload(ReflectionContext.ATTR_URL, "N1"));
        assertEquals("<lintsecN1>", XssContextAnalyzer.breakoutPayload(ReflectionContext.UNKNOWN, "N1"));
    }

    @Test
    void confirmsHtmlTextBreakoutWhenAngleBracketSurvives() {
        String body = "<p><lintsecN1></p>";
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.HTML_TEXT, body, "N1").isPresent());
    }

    @Test
    void suppressesHtmlTextWhenAngleBracketEncoded() {
        String body = "<p>&lt;lintsecN1&gt;</p>";
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.HTML_TEXT, body, "N1").isEmpty());
    }

    @Test
    void confirmsDoubleQuoteAttributeBreakout() {
        String body = "<input value=\"lintsecN1\"x\">";
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.ATTR_DOUBLE, body, "N1").isPresent());
    }

    @Test
    void suppressesDoubleQuoteAttributeWhenQuoteEncoded() {
        String body = "<input value=\"lintsecN1&quot;x\">";
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.ATTR_DOUBLE, body, "N1").isEmpty());
    }

    @Test
    void confirmsScriptBreakoutWhenClosingTagSurvives() {
        String body = "<script>var x='</script><lintsecN1>'</script>";
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.SCRIPT, body, "N1").isPresent());
    }

    @Test
    void confirmsUrlAttributeJavascriptScheme() {
        String body = "<a href=\"javascript:lintsecN1\">x</a>";
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.ATTR_URL, body, "N1").isPresent());
    }

    @Test
    void styleBreakoutIsMediumSeverity() {
        String body = "<style>.a{}</style><lintsecN1>";
        var breakout = XssContextAnalyzer.confirmBreakout(ReflectionContext.STYLE, body, "N1");
        assertTrue(breakout.isPresent());
        assertEquals(com.lintsec.domain.Severity.MEDIUM, breakout.get().severity());
    }

    @Test
    void confirmReturnsEmptyForNullBody() {
        assertTrue(XssContextAnalyzer.confirmBreakout(ReflectionContext.HTML_TEXT, null, "N1").isEmpty());
    }
```

Add the imports at the top of the test file:

```java
import static org.junit.jupiter.api.Assertions.assertTrue;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./mvnw.cmd -o -q -Dtest=XssContextAnalyzerTest test`
Expected: COMPILATION FAILURE — `breakoutPayload` / `confirmBreakout` not defined.

- [ ] **Step 3: Implement `breakoutPayload` and `confirmBreakout`**

Add these methods to `XssContextAnalyzer` (before the closing brace):

```java
    /** The Probe-2 injection value for {@code ctx}, embedding the shared {@code lintsec<nonce>} marker. */
    static String breakoutPayload(ReflectionContext ctx, String nonce) {
        String marker = "lintsec" + nonce;
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
    static java.util.Optional<Breakout> confirmBreakout(ReflectionContext ctx, String body, String nonce) {
        if (body == null) return java.util.Optional.empty();
        String marker = "lintsec" + nonce;
        return switch (ctx) {
            case HTML_TEXT, TAG_NAME, UNKNOWN -> hitIf(body.contains("<" + marker),
                    com.lintsec.domain.Severity.HIGH, "raw '<' before the canary breaks into HTML");
            case ATTR_DOUBLE -> hitIf(body.contains(marker + "\""),
                    com.lintsec.domain.Severity.HIGH, "raw '\"' after the canary breaks out of the double-quoted attribute");
            case ATTR_SINGLE -> hitIf(body.contains(marker + "'"),
                    com.lintsec.domain.Severity.HIGH, "raw ''' after the canary breaks out of the single-quoted attribute");
            case ATTR_UNQUOTED -> hitIf(body.contains(marker + " "),
                    com.lintsec.domain.Severity.HIGH, "raw space after the canary allows adding an event-handler attribute");
            case SCRIPT -> hitIf(body.contains("</script><" + marker),
                    com.lintsec.domain.Severity.HIGH, "raw '</script>' before the canary closes the script element");
            case STYLE -> hitIf(body.contains("</style><" + marker),
                    com.lintsec.domain.Severity.MEDIUM, "raw '</style>' before the canary breaks out of the style element");
            case COMMENT -> hitIf(body.contains("--><" + marker),
                    com.lintsec.domain.Severity.HIGH, "raw '-->' before the canary escapes the HTML comment");
            case ATTR_URL -> hitIf(body.contains("javascript:" + marker),
                    com.lintsec.domain.Severity.HIGH, "raw 'javascript:' scheme reflected in a URL attribute executes on navigation");
        };
    }

    private static java.util.Optional<Breakout> hitIf(boolean condition, com.lintsec.domain.Severity severity, String detail) {
        return condition ? java.util.Optional.of(new Breakout(severity, detail)) : java.util.Optional.empty();
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./mvnw.cmd -o -q -Dtest=XssContextAnalyzerTest test`
Expected: PASS (20 tests total).

- [ ] **Step 5: Commit**

```bash
git add backend/src/main/java/com/lintsec/scanner/XssContextAnalyzer.java backend/src/test/java/com/lintsec/scanner/XssContextAnalyzerTest.java
git commit -m "feat(scan): build and confirm context-specific XSS breakout probes"
```

---

## Task 4: Add `XSS_CANARY_PLAIN` payload

**Files:**
- Modify: `src/main/java/com/lintsec/scanner/PayloadId.java`
- Modify: `src/main/java/com/lintsec/scanner/PayloadCatalog.java`
- Test: `src/test/java/com/lintsec/scanner/PayloadCatalogTest.java`

- [ ] **Step 1: Read the existing PayloadCatalogTest to match its style**

Run: `cat backend/src/test/java/com/lintsec/scanner/PayloadCatalogTest.java`
Note whether it asserts every payload string. If it does, you will add one assertion in Step 4; if it only spot-checks, add a focused test for the new id.

- [ ] **Step 2: Add the enum constant**

In `PayloadId.java`, add `XSS_CANARY_PLAIN` to the enum (place it next to `XSS_CANARY_REFLECTED`):

```java
public enum PayloadId {
    XSS_CANARY_PLAIN,
    XSS_CANARY_REFLECTED,
    SQLI_SINGLE_QUOTE,
    SQLI_BALANCED,
    OPEN_REDIRECT_ABSOLUTE,
    PATH_TRAVERSAL_UNIX,
    PATH_TRAVERSAL_WINDOWS,
    CMDI_UNIX_ID,
    CMDI_WINDOWS_VER
}
```

- [ ] **Step 3: Add the catalog entries**

In `PayloadCatalog.payloadFor`, add the case (before `XSS_CANARY_REFLECTED`):

```java
            case XSS_CANARY_PLAIN -> "lintsec" + nonce;
```

In `PayloadCatalog.descriptionFor`, add:

```java
            case XSS_CANARY_PLAIN -> "Plain alphanumeric canary `lintsec{nonce}` used to locate and classify the reflection context before a context-specific breakout probe is sent.";
```

- [ ] **Step 4: Add/extend the test**

Add to `PayloadCatalogTest` (adjust to match the file's existing assertion style observed in Step 1):

```java
    @Test
    void plainCanaryIsAlphanumericWithNonce() {
        assertEquals("lintsecabc123", PayloadCatalog.payloadFor(PayloadId.XSS_CANARY_PLAIN, "abc123"));
    }
```

Ensure `import static org.junit.jupiter.api.Assertions.assertEquals;` is present (it will already be there if other tests assert payload strings).

- [ ] **Step 5: Run tests**

Run: `./mvnw.cmd -o -q -Dtest=PayloadCatalogTest test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/main/java/com/lintsec/scanner/PayloadId.java backend/src/main/java/com/lintsec/scanner/PayloadCatalog.java backend/src/test/java/com/lintsec/scanner/PayloadCatalogTest.java
git commit -m "feat(scan): add XSS_CANARY_PLAIN locate payload"
```

---

## Task 5: Rewrite `ReflectedXssModule` to the two-probe flow

**Files:**
- Modify: `src/main/java/com/lintsec/scanner/modules/ReflectedXssModule.java`

There is no module-level unit test (these modules make live HTTP calls; their logic lives in the unit-tested pure helpers, per `ErrorBasedSqliModule`). Verification here is a clean compile + the full suite staying green, plus an optional live scan.

- [ ] **Step 1: Replace the file contents**

```java
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
```

- [ ] **Step 2: Compile**

Run: `./mvnw.cmd -o -q compile`
Expected: BUILD SUCCESS.

- [ ] **Step 3: Run the full test suite**

Run: `./mvnw.cmd -o test`
Expected: BUILD SUCCESS — previous 89 tests plus the new `XssContextAnalyzerTest` (≈20) and the `PayloadCatalogTest` addition all green. (`UrlParams.replaceQueryParameters` URL-encodes the injected value; that is unchanged from the prior module and expected.)

- [ ] **Step 4: Commit**

```bash
git add backend/src/main/java/com/lintsec/scanner/modules/ReflectedXssModule.java
git commit -m "feat(scan): context-aware reflected XSS via two-probe breakout confirmation"
```

---

## Task 6: Live verification (manual, recommended — not a unit-test deliverable)

**Why:** the module makes live HTTP calls; only the pure helpers are unit-tested. Confirm end-to-end behavior against a known-reflecting target before trusting in prod. Requires a full backend restart (no DevTools — every `.java` change needs `Ctrl+C` + re-run).

- [ ] **Step 1: Restart the backend (NOT offline)**

Run (foreground, in `backend/`): `./mvnw.cmd spring-boot:run`
Expected: app starts on :8080. Do not use `-o` for `spring-boot:run`.

- [ ] **Step 2: Run a scan against a reflecting target**

Use an existing smoke script or the UI to scan a known reflected-XSS target (e.g. the public-firing-range reflected-XSS pages, or DVWA reflected-XSS with `ignoreRobots`). Confirm:
- a raw-HTML reflection is reported HIGH with detail naming "HTML body" context,
- a safely-encoded reflection produces **no** finding,
- the finding note names the surviving breakout character.

- [ ] **Step 3: Record the outcome**

Note in the session what was scanned and the observed findings. If a context misclassifies on a real page, capture the HTML snippet — it becomes a new `XssContextAnalyzerTest` fixture (extend Task 2/3 tests, do not loosen the confirmer).

---

## Self-Review Notes

- **Spec coverage:** locate+classify (Task 2), all breakout payloads + confirmer incl. suppression of encoded reflections (Task 3), `XSS_CANARY_PLAIN` (Task 4), two-probe flow over both vectors with distinct-context iteration and context-named findings (Task 5), live verification (Task 6). `<style>`=MEDIUM is enforced and tested (Task 3, `styleBreakoutIsMediumSeverity`). All maximal contexts covered: HTML_TEXT, ATTR_DOUBLE/SINGLE/UNQUOTED, ATTR_URL, SCRIPT, STYLE, COMMENT, TAG_NAME, UNKNOWN.
- **Type consistency:** `XssContextAnalyzer.classify/breakoutPayload/confirmBreakout`, `Breakout(severity, detail)`, `ReflectionContext` constants, and `PayloadId.XSS_CANARY_PLAIN` are used identically across Tasks 2–5. Marker is the single string `lintsec{nonce}` in both probes and the confirmer.
- **Known limitations (documented in spec):** one breakout probe per distinct context per param (bounded requests); DOM-based/stored XSS out of scope; TAG_NAME confirmation is heuristic (a `<lintsec` substring elsewhere could in rare cases confirm) — accepted, captured as a future test-fixture target if observed live.
