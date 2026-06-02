package com.lintsec.dto;

import java.time.Instant;

/**
 * One concrete occurrence of a grouped finding — the data that actually varies between
 * the otherwise-identical rows a scanner module emits per visited URL.
 */
public record FindingInstanceResponse(
        Long id,
        String url,
        String parameter,
        String note,
        String payloadRef,
        Instant createdAt
) {}
