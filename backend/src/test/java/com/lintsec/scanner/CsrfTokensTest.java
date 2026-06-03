package com.lintsec.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsrfTokensTest {

    @Test
    void recognisesCommonTokenNames() {
        assertTrue(CsrfTokens.looksLikeTokenName("user_token"));
        assertTrue(CsrfTokens.looksLikeTokenName("_csrf"));
        assertTrue(CsrfTokens.looksLikeTokenName("csrfmiddlewaretoken"));
        assertTrue(CsrfTokens.looksLikeTokenName("authenticity_token"));
        assertTrue(CsrfTokens.looksLikeTokenName("__RequestVerificationToken"));
        assertTrue(CsrfTokens.looksLikeTokenName("XSRF-TOKEN"));
    }

    @Test
    void rejectsOrdinaryAndNullNames() {
        assertFalse(CsrfTokens.looksLikeTokenName("username"));
        assertFalse(CsrfTokens.looksLikeTokenName("email"));
        assertFalse(CsrfTokens.looksLikeTokenName(""));
        assertFalse(CsrfTokens.looksLikeTokenName(null));
    }
}
