package com.lintsec.crawler;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashSet;
import java.util.Set;

public final class LinkExtractor {

    private LinkExtractor() {}

    public static Set<String> extractLinks(Document doc) {
        Set<String> links = new LinkedHashSet<>();
        for (Element a : doc.select("a[href]")) {
            String absHref = a.absUrl("href");
            if (absHref.isBlank()) {
                continue;
            }
            try {
                URI uri = new URI(absHref);
                String scheme = uri.getScheme();
                if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                    continue;
                }
                links.add(stripFragment(uri));
            } catch (URISyntaxException ignored) {
            }
        }
        return links;
    }

    private static String stripFragment(URI uri) throws URISyntaxException {
        return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), uri.getQuery(), null).toString();
    }
}
