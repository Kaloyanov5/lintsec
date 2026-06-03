package com.lintsec.crawler;

import java.util.List;

public record DiscoveredForm(
        String action,
        String method,
        List<FormField> fields,
        FormField submitControl,
        String pageUrl
) {
    /**
     * Stable identity for a form across re-fetches: method + action + sorted field names.
     * submitControl and pageUrl are intentionally excluded so the same form matches even if
     * its hidden token value changes between GETs.
     */
    public String signature() {
        List<String> fieldNames = fields.stream().map(FormField::name).sorted().toList();
        return method + " " + action + " " + fieldNames;
    }
}
