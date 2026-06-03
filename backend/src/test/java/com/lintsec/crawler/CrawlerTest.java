package com.lintsec.crawler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrawlerTest {

    @Test
    void skipsLogoutLinks() {
        assertTrue(Crawler.isStateChangingLink("https://t.test/logout.php"));
        assertTrue(Crawler.isStateChangingLink("https://t.test/account/signout"));
    }

    @Test
    void skipsIdsAndSecurityToggleLinks() {
        // DVWA enables PHPIDS via a GET link; once on, the IDS blocks active probe payloads
        // (the SQL single-quote), producing false negatives. The crawler must not follow it.
        assertTrue(Crawler.isStateChangingLink("https://t.test/security.php?phpids=on"));
        assertTrue(Crawler.isStateChangingLink("https://t.test/security.php?phpids=off"));
    }

    @Test
    void followsOrdinaryLinks() {
        assertFalse(Crawler.isStateChangingLink("https://t.test/vulnerabilities/sqli/"));
        assertFalse(Crawler.isStateChangingLink("https://t.test/vulnerabilities/xss_r/"));
        assertFalse(Crawler.isStateChangingLink("https://t.test/security.php")); // page itself is fine to read
    }
}
