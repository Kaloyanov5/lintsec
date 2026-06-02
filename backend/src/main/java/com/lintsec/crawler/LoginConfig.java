package com.lintsec.crawler;

/**
 * Internal login parameters for a scan. Built from the request DTO by ScanService.
 * When {@code sessionCookie} is non-blank the form-login fields are ignored and the
 * cookie is used directly.
 */
public record LoginConfig(
        String loginUrl,
        String usernameField,
        String passwordField,
        String username,
        String password,
        String successCheck,
        String sessionCookie
) {
    public boolean usesCookieInjection() {
        return sessionCookie != null && !sessionCookie.isBlank();
    }
}
