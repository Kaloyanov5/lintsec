package com.lintsec.scanner;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class UrlParams {

    private UrlParams() {}

    public static List<Map.Entry<String, String>> parseQueryParameters(URI uri) {
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return List.of();
        }

        List<Map.Entry<String, String>> parameters = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }

            int equalsIndex = pair.indexOf('=');
            String rawName = equalsIndex >= 0 ? pair.substring(0, equalsIndex) : pair;
            String rawValue = equalsIndex >= 0 ? pair.substring(equalsIndex + 1) : "";

            parameters.add(new AbstractMap.SimpleEntry<>(
                    URLDecoder.decode(rawName, StandardCharsets.UTF_8),
                    URLDecoder.decode(rawValue, StandardCharsets.UTF_8)
            ));
        }

        return parameters;
    }

    public static String replaceQueryParameters(String url, String targetParam, String newValue) {
        URI uri = URI.create(url);
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return url;
        }

        StringBuilder newQueryBuilder = new StringBuilder();
        String[] pairs = rawQuery.split("&");
        for (int i = 0; i < pairs.length; i++) {
            String[] parts = pairs[i].split("=", 2);
            String paramName = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);

            if (i > 0) {
                newQueryBuilder.append("&");
            }

            newQueryBuilder.append(parts[0]).append("=");
            if (paramName.equalsIgnoreCase(targetParam)) {
                newQueryBuilder.append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
            } else {
                newQueryBuilder.append(parts.length > 1 ? parts[1] : "");
            }
        }

        // Rebuild the URL by concatenating the raw components. We must NOT use the multi-argument
        // `new URI(scheme, authority, path, query, fragment)` constructor here: it treats its query
        // argument as decoded text and percent-encodes it again, turning our already-encoded
        // payload's "%2F" into "%252F". That double-encoding reaches the server as a literal
        // "..%2F.." instead of a real "../", silently breaking every URL-query-parameter probe.
        StringBuilder result = new StringBuilder();
        if (uri.getScheme() != null) result.append(uri.getScheme()).append("://");
        if (uri.getRawAuthority() != null) result.append(uri.getRawAuthority());
        if (uri.getRawPath() != null) result.append(uri.getRawPath());
        result.append("?").append(newQueryBuilder);
        if (uri.getRawFragment() != null) result.append("#").append(uri.getRawFragment());
        return result.toString();
    }
}
