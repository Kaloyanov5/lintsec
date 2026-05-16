package com.lintsec.scanner;

public record FindingLocation(
        String url,
        String parameter
) {
    public FindingLocation {
        if (url == null || url.isBlank()) throw new IllegalArgumentException("url required");
    }
}
