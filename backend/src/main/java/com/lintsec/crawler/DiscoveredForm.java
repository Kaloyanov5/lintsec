package com.lintsec.crawler;

import java.util.List;

public record DiscoveredForm(
        String action,
        String method,
        List<FormField> fields
) {
}
