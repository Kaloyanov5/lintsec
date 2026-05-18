package com.lintsec.dto;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Severity;
import com.lintsec.domain.VulnerabilityType;

import java.time.Instant;

public record FindingResponse(
        Long id,
        VulnerabilityType vulnerabilityType,
        Severity severity,
        String title,
        String description,
        String remediation,
        String evidenceJson,    // raw JSON string — frontend parses
        String payloadRef,
        String aiExplanation,
        Instant createdAt
) {
    public static FindingResponse from(Finding finding) {
        return new FindingResponse(
                finding.getId(),
                finding.getVulnerabilityType(),
                finding.getSeverity(),
                finding.getTitle(),
                finding.getDescription(),
                finding.getRemediation(),
                finding.getEvidenceJson(),
                finding.getPayloadRef(),
                finding.getAiExplanation(),
                finding.getCreatedAt()
        );
    }
}
