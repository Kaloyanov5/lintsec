package com.lintsec.ai;

import com.lintsec.domain.Finding;
import org.springframework.stereotype.Component;

@Component
public class FindingExplanationPromptBuilder {
    public String build(Finding finding) {
        return """
        You are a security expert explaining a vulnerability to a developer who is not a security specialist.
        
        Vulnerability: %s
        Type: %s
        Severity: %s
        Description: %s
        Remediation: %s
        
        In 2-3 sentences, explain what an attacker could do with this and why it matters. Use plain language. Do not repeat the remediation; the developer already sees it.
        """.formatted(
                finding.getTitle(),
                finding.getVulnerabilityType(),
                finding.getSeverity(),
                finding.getDescription(),
                finding.getRemediation()
        );
    }
}
