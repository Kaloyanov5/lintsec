package com.lintsec.crawler;

import org.jsoup.Jsoup;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class RobotsTxt {

    private final List<String> disallows;
    private final List<String> allows;
    private final Integer crawlDelayMs;

    private RobotsTxt(List<String> disallows, List<String> allows, Integer crawlDelayMs) {
        this.disallows = disallows;
        this.allows = allows;
        this.crawlDelayMs = crawlDelayMs;
    }

    public static RobotsTxt allowAll() {
        return new RobotsTxt(List.of(), List.of(), null);
    }

    public static RobotsTxt fetch(String baseUrl, String userAgent, int timeoutMs) {
        URI baseUri = URI.create(baseUrl);
        int port = baseUri.getPort();
        String robotsUrl = baseUri.getScheme() + "://" + baseUri.getHost() + ((port != -1) ? ":" + port : "") + "/robots.txt";
        String rawText;
        try {
            rawText = Jsoup.connect(robotsUrl).ignoreContentType(true).userAgent(userAgent).timeout(timeoutMs).execute().body();
        } catch (IOException ignored) {
            return allowAll();
        }
        return parse(rawText, userAgent);
    }

    static RobotsTxt parse(String rawText, String userAgent) {
        List<String> lines = new ArrayList<>(List.of(rawText.split("\n")));
        List<Group> groups = new ArrayList<>();
        Group current = new Group();
        boolean expectingAgents = true;

        for (String line : lines) {
            int hash = line.indexOf("#");
            if (hash >= 0) line = line.substring(0, hash);

            String[] keyValuePair = line.trim().split(":", 2);
            if (keyValuePair.length < 2) continue;
            String key = keyValuePair[0].trim().toLowerCase();
            String value = keyValuePair[1].trim();

            switch (key) {
                case "user-agent":
                    if (value.isEmpty()) break;
                    if (!expectingAgents) {
                        groups.add(current);
                        current = new Group();
                        expectingAgents = true;
                    }
                    current.userAgents.add(value.toLowerCase());
                    break;
                case "allow":
                    current.allows.add(value);
                    expectingAgents = false;
                    break;
                case "disallow":
                    if (!value.isEmpty()) current.disallows.add(value);
                    expectingAgents = false;
                    break;
                case "crawl-delay":
                    try {
                        current.crawlDelayMs = Integer.parseInt(value) * 1000;
                    } catch (NumberFormatException ignored) {
                        break;
                    }
                    expectingAgents = false;
                    break;
            }
        }
        if (!current.isEmpty()) groups.add(current);

        String ourAgentLower = userAgent.toLowerCase();
        // 1. Try to find the specific agent match
        Group matchedGroup = groups.stream()
                .filter(g -> g.userAgents.stream().anyMatch(ourAgentLower::contains))
                .findFirst()
                // 2. If not found, try to find the wildcard group
                .orElseGet(() -> groups.stream()
                        .filter(g -> g.userAgents.contains("*"))
                        .findFirst()
                        .orElse(null));

        if (matchedGroup == null) return allowAll();
        return new RobotsTxt(matchedGroup.disallows, matchedGroup.allows, matchedGroup.crawlDelayMs);
    }

    public boolean isAllowed(String path) {
        int longestAllow = -1;
        int longestDisallow = -1;
        for (String allow : allows) {
            if (path.startsWith(allow) && allow.length() > longestAllow) {
                longestAllow = allow.length();
            }
        }
        for (String disallow : disallows) {
            if (path.startsWith(disallow) && disallow.length() > longestDisallow) {
                longestDisallow = disallow.length();
            }
        }
        return longestAllow >= longestDisallow;
    }

    public Optional<Integer> crawlDelayMs() {
        return Optional.ofNullable(crawlDelayMs);
    }

    private static final class Group {
        final List<String> userAgents = new ArrayList<>();
        final List<String> allows = new ArrayList<>();
        final List<String> disallows = new ArrayList<>();
        Integer crawlDelayMs = null;

        boolean isEmpty() {
            return userAgents.isEmpty() && allows.isEmpty()
                    && disallows.isEmpty() && crawlDelayMs == null;
        }
    }
}
