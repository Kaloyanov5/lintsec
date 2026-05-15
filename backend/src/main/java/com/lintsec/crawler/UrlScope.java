package com.lintsec.crawler;

import java.net.URI;

public class UrlScope {

    private final String baseHost;
    private final String baseScheme;

    public UrlScope(String startUrl) {
        URI uri = URI.create(startUrl);
        String host = uri.getHost();
        if (host == null) {
            throw new IllegalArgumentException("startUrl has no host");
        }
        this.baseHost = host;
        this.baseScheme = uri.getScheme();
    }

    public boolean isInScope(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            String scheme = uri.getScheme();
            return host != null && scheme != null && host.equalsIgnoreCase(baseHost) && scheme.equalsIgnoreCase(baseScheme);
        } catch (Exception e) {
            return false;
        }
    }
}
