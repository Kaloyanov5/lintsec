package com.lintsec.dto;

public record ScanEvent(
        Long scanId,
        EventType type,
        int pagesCrawled,
        int findingsCount,
        String message       // optional context, e.g. error msg for FAILED
) {
    public enum EventType {
        STARTED,
        CRAWL_COMPLETE,
        SCAN_COMPLETE,
        FAILED
    }
}
