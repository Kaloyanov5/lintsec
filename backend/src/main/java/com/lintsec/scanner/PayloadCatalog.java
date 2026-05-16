package com.lintsec.scanner;

public final class PayloadCatalog {
    private PayloadCatalog() {}

    public static String payloadFor(PayloadId id, String nonce) {
        return switch (id) {
            case XSS_CANARY_REFLECTED -> "lintsec_canary_" + nonce;
            case SQLI_SINGLE_QUOTE -> "'";
            case OPEN_REDIRECT_ABSOLUTE -> "https://lintsec-test.invalid/";
        };
    }

    public static String descriptionFor(PayloadId id) {
        return switch (id) {
            case XSS_CANARY_REFLECTED -> "Unique canary string injected; flagged if reflected unencoded.";
            case SQLI_SINGLE_QUOTE -> "Single-quote injected to trigger SQL syntax error in unparameterized query.";
            case OPEN_REDIRECT_ABSOLUTE -> "Absolute URL to invalid domain; flagged if server issues 30x Location to it.";
        };
    }
}
