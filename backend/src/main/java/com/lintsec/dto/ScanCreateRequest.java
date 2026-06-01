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

        // Opt-in flag (pentest sandboxes that Disallow: /). Optional: a wrapper so an
        // absent value deserializes to null instead of tripping FAIL_ON_NULL_FOR_PRIMITIVES,
        // then we default it to false. Keeps the genuinely-required primitives above strict.
        Boolean ignoreRobots
) {
    public ScanCreateRequest {
        if (ignoreRobots == null) ignoreRobots = false;
    }
}
