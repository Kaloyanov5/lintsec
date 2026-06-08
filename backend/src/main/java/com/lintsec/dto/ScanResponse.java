package com.lintsec.dto;

import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanStatus;

import java.time.Instant;

public record ScanResponse(
        Long id,
        String targetUrl,
        ScanStatus status,
        int maxDepth,
        int maxPages,
        int requestDelayMs,
        int pagesCrawled,
        boolean authenticated,
        boolean cancelRequested,
        String errorMessage,    // null when not failed
        Instant startedAt,      // null when pending
        Instant completedAt,    // null when not complete/failed
        Instant createdAt
) {
    public static ScanResponse from(Scan scan) {
        return new ScanResponse(
                scan.getId(),
                scan.getTargetUrl(),
                scan.getStatus(),
                scan.getMaxDepth(),
                scan.getMaxPages(),
                scan.getRequestDelayMs(),
                scan.getPagesCrawled(),
                scan.isAuthenticated(),
                scan.isCancelRequested(),
                scan.getErrorMessage(),
                scan.getStartedAt(),
                scan.getCompletedAt(),
                scan.getCreatedAt()
        );
    }
}
