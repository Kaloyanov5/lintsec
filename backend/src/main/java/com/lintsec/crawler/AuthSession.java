package com.lintsec.crawler;

import org.jsoup.Connection;

import java.util.Map;

/**
 * Immutable carrier for an authenticated session: the cookie jar captured at login,
 * applied to every outbound request so the whole scan runs as the logged-in user.
 * {@link #anonymous()} is the empty session used by unauthenticated scans.
 */
public record AuthSession(Map<String, String> cookies) {

    public AuthSession {
        cookies = cookies == null ? Map.of() : Map.copyOf(cookies);
    }

    public static AuthSession anonymous() {
        return new AuthSession(Map.of());
    }

    public boolean isAuthenticated() {
        return !cookies.isEmpty();
    }

    /** Attach this session's cookies to a JSoup connection. No-op when anonymous. */
    public void applyTo(Connection connection) {
        if (!cookies.isEmpty()) {
            connection.cookies(cookies);
        }
    }
}
