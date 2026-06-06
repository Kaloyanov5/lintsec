package com.lintsec.dto;

import com.lintsec.domain.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanStatsResponseTest {

    @Test
    void zeroFillsAllSeveritiesWhenNoFindings() {
        ScanStatsResponse stats = ScanStatsResponse.from(0L, 0L, List.of());

        assertEquals(0L, stats.totalScans());
        assertEquals(0L, stats.completedScans());
        assertEquals(0L, stats.totalFindings());
        for (Severity s : Severity.values()) {
            assertEquals(0L, stats.findingsBySeverity().get(s), "expected 0 for " + s);
        }
    }

    @Test
    void sumsTotalAndMapsPresentSeverities() {
        List<Object[]> rows = List.of(
                new Object[]{Severity.CRITICAL, 3L},
                new Object[]{Severity.HIGH, 9L},
                new Object[]{Severity.LOW, 40L}
        );

        ScanStatsResponse stats = ScanStatsResponse.from(12L, 7L, rows);

        assertEquals(12L, stats.totalScans());
        assertEquals(7L, stats.completedScans());
        assertEquals(52L, stats.totalFindings());
        assertEquals(3L, stats.findingsBySeverity().get(Severity.CRITICAL));
        assertEquals(9L, stats.findingsBySeverity().get(Severity.HIGH));
        assertEquals(0L, stats.findingsBySeverity().get(Severity.MEDIUM));
        assertEquals(40L, stats.findingsBySeverity().get(Severity.LOW));
        assertEquals(0L, stats.findingsBySeverity().get(Severity.INFO));
    }
}
