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
