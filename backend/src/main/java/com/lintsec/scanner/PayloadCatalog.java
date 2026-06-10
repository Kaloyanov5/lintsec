package com.lintsec.scanner;

public final class PayloadCatalog {
    private PayloadCatalog() {}

    public static String payloadFor(PayloadId id, String nonce) {
        return switch (id) {
            case XSS_CANARY_REFLECTED -> "<lintsec_canary_" + nonce + ">";
            case SQLI_SINGLE_QUOTE -> "'";
            case SQLI_BALANCED -> "''";
            case OPEN_REDIRECT_ABSOLUTE -> "https://lintsec-test.invalid/";
            case PATH_TRAVERSAL_UNIX -> "../../../../../../../../etc/passwd";
            case PATH_TRAVERSAL_WINDOWS -> "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini";
            case CMDI_UNIX_ID -> ";id";
            case CMDI_WINDOWS_VER -> "& ver";
        };
    }

    public static String descriptionFor(PayloadId id) {
        return switch (id) {
            case XSS_CANARY_REFLECTED -> "Canary payload is `<lintsec_canary_{nonce}>`; flagged if reflected without output encoding/escaping.";
            case SQLI_SINGLE_QUOTE -> "Single-quote injected to trigger SQL syntax error in unparameterized query.";
            case SQLI_BALANCED -> "Balanced two single-quotes; the control payload that should NOT error if the single-quote finding is real.";
            case OPEN_REDIRECT_ABSOLUTE -> "Absolute URL to invalid domain; flagged if server issues 30x Location to it.";
            case PATH_TRAVERSAL_UNIX -> "Deep ../ traversal to /etc/passwd; flagged if the response contains the passwd 'root:...:0:0:' signature.";
            case PATH_TRAVERSAL_WINDOWS -> "Deep ..\\ traversal to windows\\win.ini; flagged if the response contains a win.ini section header.";
            case CMDI_UNIX_ID -> "Shell metacharacter + 'id'; flagged if the response contains 'uid=...gid=' command output.";
            case CMDI_WINDOWS_VER -> "Shell metacharacter + 'ver'; flagged if the response contains the Windows version banner.";
        };
    }
}
