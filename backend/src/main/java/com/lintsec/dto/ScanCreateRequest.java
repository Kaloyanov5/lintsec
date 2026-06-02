package com.lintsec.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

public record ScanCreateRequest(

        @NotBlank
        @Size(max = 2048)
        @Pattern(regexp = "^https?://[^\\s]+$")
        String targetUrl,

        @Min(0)
        @Max(3)
        int maxDepth,

        @Min(1)
        @Max(50)
        int maxPages,

        @Min(0)
        @Max(5000)
        int requestDelayMs,

        @AssertTrue(message = "must confirm ownership")
        boolean ownershipConfirmed,

        // Opt-in flag (pentest sandboxes that Disallow: /). Optional wrapper so an absent
        // value deserializes to null instead of tripping FAIL_ON_NULL_FOR_PRIMITIVES.
        Boolean ignoreRobots,

        // Optional authenticated-scan config; null => anonymous scan (unchanged behavior).
        @Valid
        AuthConfig auth
) {
    public ScanCreateRequest {
        if (ignoreRobots == null) ignoreRobots = false;
    }

    /**
     * Authenticated-scan parameters. Requiredness is conditional (a pasted session cookie
     * replaces the form-login fields), so the guards live in the compact constructor rather
     * than as field annotations.
     */
    public record AuthConfig(
            String loginUrl,
            String usernameField,
            String passwordField,
            String username,
            String password,
            String successCheck,
            String sessionCookie
    ) {
        public AuthConfig {
            boolean hasCookie = sessionCookie != null && !sessionCookie.isBlank();
            if (!hasCookie) {
                if (isBlank(loginUrl) || isBlank(usernameField) || isBlank(passwordField)
                        || isBlank(username) || isBlank(password)) {
                    throw new IllegalArgumentException(
                            "auth requires loginUrl, usernameField, passwordField, username and password "
                                    + "(or a sessionCookie)");
                }
                if (!loginUrl.matches("^https?://[^\\s]+$")) {
                    throw new IllegalArgumentException("auth.loginUrl must be a valid http(s) URL");
                }
            }
        }

        private static boolean isBlank(String s) {
            return s == null || s.isBlank();
        }
    }
}
