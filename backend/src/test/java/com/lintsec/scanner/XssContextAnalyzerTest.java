package com.lintsec.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void urlRefineDoesNotUpgradeNonUrlDoubleQuotedAttribute() {
        // Same double-quoted shape as the ATTR_URL test, but a non-URL attribute name must stay ATTR_DOUBLE.
        String body = "<input value=\"CANARY\">";
        assertEquals(ReflectionContext.ATTR_DOUBLE, XssContextAnalyzer.classify(body, body.indexOf("CANARY")));
    }

    @Test
    void closedStyleBeforeReflectionIsNotStyle() {
        String body = "<style>.a{}</style><p>CANARY</p>";
        assertEquals(ReflectionContext.HTML_TEXT, XssContextAnalyzer.classify(body, body.indexOf("CANARY")));
    }
}
