package com.lintsec.crawler;

/** Thrown when a scan's login step cannot be completed or verified. */
public class AuthenticationException extends RuntimeException {
    public AuthenticationException(String message) {
        super(message);
    }
}
