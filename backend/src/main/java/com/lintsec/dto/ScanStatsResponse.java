package com.lintsec.dto;

import com.lintsec.domain.Severity;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Per-user aggregate for the dashboard. {@code findingsBySeverity} always contains all five
 * {@link Severity} keys (zero-filled); {@code totalFindings} is the sum of those values.
 * Serialized by Jackson with enum-name keys to match the frontend {@code FindingsBySeverity}.
 */
public record ScanStatsResponse(
        long totalScans,
        long completedScans,
        long totalFindings,
        Map<Severity, Long> findingsBySeverity
) {
    /**
     * @param severityRows rows of {@code [Severity, count]} from the grouped-count query;
     *                     absent severities are zero-filled.
     */
    public static ScanStatsResponse from(long totalScans, long completedScans, List<Object[]> severityRows) {
        EnumMap<Severity, Long> bySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            bySeverity.put(s, 0L);
        }
        long total = 0L;
        for (Object[] row : severityRows) {
            Severity severity = (Severity) row[0];
            long count = ((Number) row[1]).longValue();
            bySeverity.put(severity, count);
            total += count;
        }
        return new ScanStatsResponse(totalScans, completedScans, total, bySeverity);
    }
}
