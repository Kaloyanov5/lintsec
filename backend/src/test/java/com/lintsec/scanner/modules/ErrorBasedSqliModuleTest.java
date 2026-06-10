package com.lintsec.scanner.modules;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ErrorBasedSqliModuleTest {

    private static final String MYSQL_ERROR =
            "<b>Warning</b>: You have an error in your SQL syntax near ''' at line 1";
    private static final String CLEAN = "<html><body>Welcome, results for your search.</body></html>";

    @Test
    void flagsWhenOnlyBrokenPayloadErrors() {
        // Error appears under ' but not in baseline or the balanced '' control → real injection.
        assertEquals(Optional.of("MySQL"),
                ErrorBasedSqliModule.confirmInjection(CLEAN, MYSQL_ERROR, CLEAN));
    }

    @Test
    void doesNotFlagWhenPageAlwaysShowsError() {
        // The page renders the same DB error regardless of payload (e.g. a broken endpoint or docs).
        assertEquals(Optional.empty(),
                ErrorBasedSqliModule.confirmInjection(MYSQL_ERROR, MYSQL_ERROR, MYSQL_ERROR));
    }

    @Test
    void doesNotFlagWhenBalancedPayloadAlsoErrors() {
        // If the balanced control also errors, the single quote isn't what broke the query.
        assertEquals(Optional.empty(),
                ErrorBasedSqliModule.confirmInjection(CLEAN, MYSQL_ERROR, MYSQL_ERROR));
    }

    @Test
    void doesNotFlagWhenNoError() {
        assertEquals(Optional.empty(),
                ErrorBasedSqliModule.confirmInjection(CLEAN, CLEAN, CLEAN));
    }
}
