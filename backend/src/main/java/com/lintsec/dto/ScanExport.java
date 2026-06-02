package com.lintsec.dto;

import com.lintsec.domain.Severity;

import java.util.List;
import java.util.Map;

/**
 * The unified export document for a scan. Serialized directly as the JSON export and walked by
 * {@link com.lintsec.report.ScanReportPdfRenderer} for the PDF export, so the two formats can
 * never drift.
 *
 * @param severityCounts number of distinct issues (groups) per severity
 * @param totalFindings  total occurrences across all groups (sum of group counts)
 */
public record ScanExport(
        ScanResponse scan,
        Map<Severity, Integer> severityCounts,
        int totalFindings,
        List<FindingGroupResponse> groups
) {}
