package com.lintsec.dto;

import com.lintsec.domain.Severity;
import com.lintsec.domain.VulnerabilityType;

import java.util.List;

/**
 * A set of findings that share the same {@code (vulnerabilityType, severity, title)} collapsed
 * into a single issue. The descriptive fields are identical across the group; the per-occurrence
 * detail lives in {@link #instances()}.
 */
public record FindingGroupResponse(
        VulnerabilityType vulnerabilityType,
        Severity severity,
        String title,
        String description,
        String remediation,
        String aiExplanation,
        int count,
        List<FindingInstanceResponse> instances
) {}
