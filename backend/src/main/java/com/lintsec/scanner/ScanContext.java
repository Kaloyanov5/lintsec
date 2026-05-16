package com.lintsec.scanner;

public record ScanContext(
        String userAgent,
        int timeoutMs,
        boolean followRedirects
) {
    public ScanContext {
        if (userAgent == null || userAgent.isBlank()) throw new IllegalArgumentException("userAgent required");
        if (timeoutMs <= 0) throw new IllegalArgumentException("timeoutMs must be positive");
    }
}
