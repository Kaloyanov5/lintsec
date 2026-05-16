package com.lintsec.scanner;

import com.lintsec.domain.Severity;

public record ScanFinding(
        String title,
        Severity severity,
        String module,
        FindingLocation location,
        String description,
        String remediation,
        PayloadId evidenceRef,  // nullable
        String evidenceNote // nullable
) {
    public ScanFinding {
        if (title == null || title.isBlank()) throw new IllegalArgumentException("title required");
        if (severity == null) throw new IllegalArgumentException("severity required");
        if (module == null || module.isBlank()) throw new IllegalArgumentException("module required");
        if (location == null) throw new IllegalArgumentException("location required");
    }
}
