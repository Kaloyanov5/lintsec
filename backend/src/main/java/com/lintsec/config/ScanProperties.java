package com.lintsec.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Scan lifecycle limits ({@code lintsec.scan.*}). Previously {@code max-duration-minutes} sat in
 * YAML but was never bound, so scans had no wall-clock ceiling; this record makes the limits real.
 */
@ConfigurationProperties(prefix = "lintsec.scan")
public record ScanProperties(
        int maxDurationMinutes,
        int maxConcurrentPerUser
) {
    public ScanProperties {
        if (maxDurationMinutes <= 0) throw new IllegalArgumentException("maxDurationMinutes must be positive");
        if (maxConcurrentPerUser <= 0) throw new IllegalArgumentException("maxConcurrentPerUser must be positive");
    }
}
