package com.lintsec.dto;

import jakarta.validation.constraints.*;

public record ScanCreateRequest(

        @NotBlank
        @Size(max = 2048)
        @Pattern(regexp = "^https?://[^\\s]+$")
        String targetUrl,

        @Min(0)
        @Max(3)
        int maxDepth,

        @Min(1)
        @Max(50)
        int maxPages,

        @Min(0)
        @Max(5000)
        int requestDelayMs,

        @AssertTrue(message = "must confirm ownership")
        boolean ownershipConfirmed,

        boolean ignoreRobots
) {
}
