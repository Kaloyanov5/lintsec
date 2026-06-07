package com.lintsec.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UrlParamsTest {

    @Test
    void encodesPayloadExactlyOnce() {
        // Slashes must be encoded once as %2F, NOT double-encoded as %252F. Double-encoding
        // reaches the server as a literal "..%2F.." instead of a real "../", silently breaking
        // every URL-query-parameter probe (path traversal, SQLi, XSS, open redirect).
        String result = UrlParams.replaceQueryParameters(
                "http://t.test/fi/?page=include.php", "page", "../../etc/passwd");
        assertEquals("http://t.test/fi/?page=..%2F..%2Fetc%2Fpasswd", result);
    }

    @Test
    void encodesSpecialCharactersOnce() {
        String result = UrlParams.replaceQueryParameters(
                "http://t.test/p?id=1", "id", "1'");
        assertEquals("http://t.test/p?id=1%27", result);
    }

    @Test
    void preservesOtherParameters() {
        String result = UrlParams.replaceQueryParameters(
                "http://t.test/p?a=1&b=2&c=3", "b", "x/y");
        assertEquals("http://t.test/p?a=1&b=x%2Fy&c=3", result);
    }

    @Test
    void targetsParameterCaseInsensitively() {
        String result = UrlParams.replaceQueryParameters(
                "http://t.test/p?Page=x", "page", "../y");
        assertEquals("http://t.test/p?Page=..%2Fy", result);
    }

    @Test
    void returnsUrlUnchangedWhenNoQuery() {
        String url = "http://t.test/path";
        assertEquals(url, UrlParams.replaceQueryParameters(url, "page", "payload"));
    }
}
